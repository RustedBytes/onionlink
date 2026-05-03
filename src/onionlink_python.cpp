#define ONIONLINK_NO_MAIN
#include "onionlink.cpp"

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <mutex>

namespace py = pybind11;

namespace {

void ensure_sodium_initialized() {
  static std::once_flag once;
  static bool ok = false;
  std::call_once(once, [] { ok = sodium_init() >= 0; });
  require(ok, "libsodium initialization failed");
}

Options make_options(const std::string &bootstrap, const std::string &consensus_file,
                     int timeout_ms, bool verbose) {
  Options opt;
  opt.bootstrap = parse_hostport(bootstrap);
  opt.consensus_file = consensus_file;
  opt.timeout_ms = timeout_ms;
  opt.verbose = verbose;
  return opt;
}

class PythonSession {
public:
  PythonSession(const std::string &bootstrap, const std::string &consensus_file,
                int timeout_ms, bool verbose)
      : opt_(make_options(bootstrap, consensus_file, timeout_ms, verbose)) {
    ensure_sodium_initialized();
    consensus_ = load_consensus(opt_);
    hydrate_microdescriptors(consensus_, opt_.bootstrap, opt_.timeout_ms,
                             opt_.verbose);
  }

  py::bytes request(const std::string &onion, uint16_t port, py::bytes payload,
                    size_t response_limit) const {
    std::string payload_string = payload;
    Bytes outbound(payload_string.begin(), payload_string.end());
    Bytes inbound;
    {
      py::gil_scoped_release release;
      inbound = request_bytes(onion, port, outbound, response_limit);
    }
    return py::bytes(reinterpret_cast<const char *>(inbound.data()),
                     inbound.size());
  }

  py::bytes http_get(const std::string &onion, uint16_t port,
                     const std::string &path, size_t response_limit) const {
    std::string normalized_path = path.empty() ? "/" : path;
    if (normalized_path[0] != '/') {
      normalized_path.insert(normalized_path.begin(), '/');
    }
    std::ostringstream req;
    req << "GET " << normalized_path << " HTTP/1.0\r\n"
        << "Host: " << lower(onion) << "\r\n"
        << "Connection: close\r\n\r\n";
    Bytes inbound;
    {
      py::gil_scoped_release release;
      inbound = request_bytes(onion, port, from_string(req.str()), response_limit);
    }
    return py::bytes(reinterpret_cast<const char *>(inbound.data()),
                     inbound.size());
  }

private:
  Bytes request_bytes(const std::string &onion, uint16_t port,
                      const Bytes &outbound, size_t response_limit) const {
    Options opt = opt_;
    opt.onion = onion;
    opt.port = port;

    Consensus consensus;
    {
      std::lock_guard<std::mutex> lock(consensus_mu_);
      consensus = consensus_;
    }

    OnionAddress onion_addr = parse_onion_address(opt.onion);
    HsPeriodKeys keys = derive_hs_period_keys(consensus, onion_addr);
    DescriptorFetchResult desc =
        fetch_hidden_service_descriptor(consensus, keys, opt.timeout_ms,
                                        opt.verbose);
    RendezvousStream stream = connect_onion_service_with_retries(
        opt, consensus, desc.descriptor, keys, {desc.guard});
    constexpr uint16_t stream_id = 1;
    stream.begin(stream_id, opt.port);
    if (!outbound.empty()) {
      stream.send_data(stream_id, outbound);
    }
    return stream.read_until_end(stream_id, response_limit);
  }

  Options opt_;
  mutable std::mutex consensus_mu_;
  Consensus consensus_;
};

} // namespace

PYBIND11_MODULE(_native, m, py::mod_gil_not_used()) {
  m.doc() = "Native Linux bindings for onionlink";

  py::class_<PythonSession>(m, "Session")
      .def(py::init<const std::string &, const std::string &, int, bool>(),
           py::arg("bootstrap") = "128.31.0.39:9131",
           py::arg("consensus_file") = "", py::arg("timeout_ms") = 30000,
           py::arg("verbose") = false)
      .def("request", &PythonSession::request, py::arg("onion"),
           py::arg("port"), py::arg("payload") = py::bytes(),
           py::arg("response_limit") = 4 * 1024 * 1024)
      .def("http_get", &PythonSession::http_get, py::arg("onion"),
           py::arg("port") = 80, py::arg("path") = "/",
           py::arg("response_limit") = 4 * 1024 * 1024);
}
