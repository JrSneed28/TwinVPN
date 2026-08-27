// A second, independent protobuf implementation for cross-checking.
// Reads one JSON request on stdin, writes one JSON response on stdout.
const path = require("path");
const protobuf = require("protobufjs");

const PROTO_DIR = path.resolve(__dirname, "..", "proto");
const FILES = require("fs")
  .readdirSync(path.join(PROTO_DIR, "twinvpn", "v1"))
  .filter((f) => f.endsWith(".proto"))
  .map((f) => `twinvpn/v1/${f}`);

const root = new protobuf.Root();
root.resolvePath = (_origin, target) => path.resolve(PROTO_DIR, target);
root.loadSync(FILES);

let input = "";
process.stdin.on("data", (d) => (input += d));
process.stdin.on("end", () => {
  let req;
  try {
    req = JSON.parse(input);
    const T = root.lookupType(req.type);
    if (req.op === "encode") {
      // fromObject applies the JSON name mapping, matching buf's json format.
      const msg = T.fromObject(req.obj);
      const buf = T.encode(msg).finish();
      process.stdout.write(JSON.stringify({ hex: Buffer.from(buf).toString("hex") }));
    } else if (req.op === "decode") {
      const msg = T.decode(Buffer.from(req.hex, "hex"));
      process.stdout.write(
        JSON.stringify({ obj: T.toObject(msg, { longs: String, enums: Number }) })
      );
    } else if (req.op === "roundtrip_preserve") {
      // protobufjs keeps unknown fields when the type is decoded and re-encoded
      // through the reader's unknown-field buffer.
      const msg = T.decode(Buffer.from(req.hex, "hex"));
      const out = T.encode(msg).finish();
      process.stdout.write(JSON.stringify({ hex: Buffer.from(out).toString("hex") }));
    } else {
      throw new Error("unknown op " + req.op);
    }
  } catch (e) {
    process.stderr.write(String((e && e.stack) || e));
    process.exit(1);
  }
});
