The large AWS vectors used by the tests are reconstructed independently from
the public SigV4 streaming examples, using the documented public example
credential `AKIAIOSFODNN7EXAMPLE` and its corresponding example secret. The
small signed-payload and signed-trailer files in this directory are local
conformance fixtures, not byte-for-byte copies of those AWS examples; their
values are local and are never labelled as official vectors.
Sources:

* https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming.html
* https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming-trailers.html

The compact fixtures are executable local vectors. Their exact key, seed,
timestamp, scope, mode, decoded length, declared trailer, and tampering state
are in manifest.json; the body files use literal CRLF delimiters. Tests load
these immutable bytes directly into the verifier and assert the manifest's
declared outcome. Tampered files contain actual mutated chunk, zero-chunk,
trailer, framing, length, or physical-tail bytes.
The large AWS vectors are independently reconstructed because no corresponding
large AWS body files are stored here. All compact signed, unsigned, and
negative files are local protocol conformance fixtures; none are presented as
AWS examples.
