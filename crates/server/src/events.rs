use async_stream::stream;
use axum::{response::Sse, response::sse::Event};
use futures_util::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::routes::{ApiResult, RequestAuth};

pub async fn events(
    auth: RequestAuth,
) -> ApiResult<Sse<impl Stream<Item = std::result::Result<Event, std::convert::Infallible>>>> {
    let receiver = auth.authenticated.context.subscribe();
    let events = BroadcastStream::new(receiver).filter_map(|event| event.ok());
    let stream = stream! {
        yield Ok(Event::default().event("ready").data("{}"));
        tokio::pin!(events);
        while let Some(event) = events.next().await {
            let data = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
            yield Ok(Event::default().event("salvage").data(data));
        }
    };
    Ok(Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("heartbeat"),
    ))
}
