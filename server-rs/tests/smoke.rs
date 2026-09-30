mod common;
use common::TestServer;

#[tokio::test]
async fn server_starts_and_responds_healthy() {
    let server = TestServer::start().await;
    let client = server.client();
    let response = client.get(server.url("/healthz")).send().await.unwrap();
    assert_eq!(response.status(), 200);
}
