use {
    std::io::{Cursor, Read},

    flate2::{
        Compression,
        read::{GzDecoder, GzEncoder},
    },
    futures::{
        // Extension trait for futures 0.1 futures, adding the `.compat()` method
        // which allows us to use `.await` on 0.1 futures.
        compat::Future01CompatExt,
        // Extension traits providing additional methods on futures.
        // `FutureExt` adds methods that work for all futures, whereas
        // `TryFutureExt` adds methods to futures that return `Result` types.
        future::{FutureExt, TryFutureExt},
    },
    hyper::{
        // Miscellaneous types from Hyper for working with HTTP.
        Body, Client, Request, Response, Server, StatusCode, Uri,
        http::header::{
            HeaderMap,
            HeaderName,
            HeaderValue,

            CONNECTION,
            CONTENT_SECURITY_POLICY,
            CONTENT_TYPE,
            CONTENT_ENCODING,
            HOST,
            //KEEP_ALIVE,
            PROXY_AUTHENTICATE,
            PROXY_AUTHORIZATION,
            TE,
            //TRAILERS,
            TRANSFER_ENCODING,
            UPGRADE,

        },

        rt::Stream,

        // This function turns a closure which returns a future into an
        // implementation of the the Hyper `Service` trait, which is an
        // asynchronous function from a generic `Request` to a `Response`.
        service::service_fn,

        // A function which runs a future to completion using the Hyper runtime.
        rt::run,
    },
    hyper_tls::HttpsConnector,
    log::{info, debug, error},
    lol_html::{element, HtmlRewriter, Settings},
    std::net::SocketAddr,
};

const DOMAIN: &str = "www.rust-lang.org";

async fn serve_req(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let mut req_parts = req.uri().clone().into_parts();

    req_parts.scheme = Some("https".parse().unwrap());
    req_parts.authority = Some(DOMAIN.parse().unwrap());
    req_parts.path_and_query = req_parts.path_and_query.clone();

    let proxy_uri = Uri::from_parts(req_parts).expect("failed to build URI");
    let proxy_body = Body::default(); // req.body()

    print!("Got request at {:?}, proxying to {:?} -- ", req.uri(), proxy_uri);
    let https = HttpsConnector::new(4).unwrap();
    let client = Client::builder().build::<_, hyper::Body>(https);

    let proxy_req = {
        let mut proxy_req_builder = Request::builder();
        proxy_req_builder.method(req.method())
        .uri(proxy_uri);

        let proxy_headers = create_proxy_headers(req.headers());
        for (key, value) in proxy_headers.iter() {
            if key == HOST {
                continue
            }
            proxy_req_builder.header(key, value);
        }
        proxy_req_builder.header(HOST, DOMAIN);

        proxy_req_builder
            .body(proxy_body)
    }.unwrap();
    let resp = client.request(proxy_req).compat().await;
    match resp {
        Ok(mut resp) => {
            let headers = resp.headers_mut();
            headers.remove(CONTENT_SECURITY_POLICY);

            let (parts, body) = resp.into_parts();
            let content_encoding = parts.headers.get(CONTENT_ENCODING).map(|v| v.as_bytes());
            let content_type = parts.headers.get(CONTENT_TYPE).map(|v| v.as_bytes());

            println!("{}", parts.status.as_str());

            let entire_body: Vec<u8> = {
                let body_bytes = body.map(|c| c.into_bytes()).concat2().compat().await?.to_vec();

                match content_encoding {
                    Some(b"gzip") => {
                        // TODO gzip decompress body_bytes
                        let mut d = GzDecoder::new(Cursor::new(body_bytes));

                        let mut buf = vec![];
                        d.read_to_end(&mut buf).unwrap();
                        buf
                    }
                    Some(ctype) => panic!("Unsupported Content-Type: {}", std::str::from_utf8(ctype).unwrap_or("<invalid header>")),
                    None => body_bytes,
                }
            };
            let new_body = if content_type == Some(b"text/html") || content_type == Some(b"text/html; charset=utf-8") {

                println!("\n\n{:?}\n\n", &entire_body);
                println!("\n\n{}\n\n", std::str::from_utf8(&entire_body).unwrap());
                let new_body_bytes = rewrite_body(&entire_body).unwrap();

                // Body::from(new_body_bytes)
                new_body(&new_body_bytes, content_encoding)
            } else {
                // Body::from(entire_body)
                new_body(&entire_body, content_encoding)
            };

            Ok(Response::from_parts(parts, new_body))
        }
        Err(err) => {
            println!("Error: {}", err);
            let body = Body::from(err.to_string());
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(body)
                .unwrap()
            )
        }
    }
}

fn new_body(body_bytes: &[u8], content_encoding: Option<&[u8]>) -> Body {
                let bb = match content_encoding {
                    Some(b"gzip") => {
                        let mut d = GzEncoder::new(Cursor::new(body_bytes), Compression::default());

                        let mut buf = vec![];
                        d.read_to_end(&mut buf).unwrap();
                        buf
                    }
                    Some(ctype) => panic!("Unsupported Content-Type: {}", std::str::from_utf8(ctype).unwrap_or("<invalid header>")),
                    None => body_bytes.to_vec(),
                };
                Body::from(bb)
}

async fn run_server(addr: SocketAddr) {
    info!("Listening on http://{}", addr);

    // Create a server bound on the provided address
    let serve_future = Server::bind(&addr)
        // Serve requests using our `async serve_req` function.
        // `serve` takes a closure which returns a type implementing the
        // `Service` trait. `service_fn` returns a value implementing the
        // `Service` trait, and accepts a closure which goes from request
        // to a future of the response. To use our `serve_req` function with
        // Hyper, we have to box it and put it in a compatability
        // wrapper to go from a futures 0.3 future (the kind returned by
        // `async fn`) to a futures 0.1 future (the kind used by Hyper).
        .serve(|| service_fn(|req| serve_req(req).boxed().compat()));

    // Wait for the server to complete serving or exit with an error.
    // If an error occurred, print it to stderr.
    if let Err(e) = serve_future.compat().await {
        error!("server error: {}", e);
    }
}

fn is_hop_header(header: &HeaderName) -> bool {
    const HEADERS: &[HeaderName] = &[
        CONNECTION,
        CONTENT_SECURITY_POLICY,
        //KEEP_ALIVE,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        //TRAILERS,
        TRANSFER_ENCODING,
        UPGRADE,
    ];

    HEADERS.contains(header)
}

/// Returns a clone of the headers without the [hop-by-hop headers].
///
/// [hop-by-hop headers]: http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
fn create_proxy_headers(headers: &HeaderMap<HeaderValue>) -> HeaderMap<HeaderValue> {
    let mut result = HeaderMap::new();
    for (k, v) in headers.iter() {
        if !is_hop_header(k) {
            result.insert(k.clone(), v.clone());
        }
    }
    result
}

fn rewrite_body(body: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut output = vec![];

    let initial_len = body.len();

    let mut rewriter = HtmlRewriter::try_new(
        Settings {
            element_content_handlers: vec![
                element!("a[href]", |el| {
                    debug!("a[href]");
                    let href = el
                        .get_attribute("href")
                        .expect("href was required")
                        .replace("http:", "https:");

                    el.set_attribute("href", &href)?;

                    Ok(())
                })
            ],
            ..Settings::default()
        },
        |c: &[u8]| output.extend_from_slice(c)
    )?;

    rewriter.write(body)?;
    rewriter.end()?;
    debug!("Rewritten request len {} to len {}", initial_len, output.len());

    Ok(output)
}

fn main() {
    env_logger::init();
    // Set the address to run our socket on.
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // Call our `run_server` function, which returns a future.
    // As with every `async fn`, for `run_server` to do anything,
    // the returned future needs to be run. Additionally,
    // we need to convert the returned future from a futures 0.3 future into a
    // futures 0.1 future.
    let futures_03_future = run_server(addr);
    let futures_01_future = futures_03_future.unit_error().boxed().compat();

    // Finally, we can run the future to completion using the `run` function
    // provided by Hyper.
    run(futures_01_future);
}
