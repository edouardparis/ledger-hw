use async_trait::async_trait;
use ledger_hw::Status;

#[async_trait]
pub trait Transport {
    type Err;
    async fn exchange(&self, req: &[u8]) -> Result<Vec<u8>, Self::Err>;

    // wrapper on top of exchange.
    async fn send(
        &self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<(Vec<u8>, Status), TransportError<Self::Err>> {
        let mut request = vec![cla, ins, p1, p2, data.len() as u8];
        request.extend(data);
        let mut res = self
            .exchange(&request)
            .await
            .map_err(|e| TransportError::Transport::<Self::Err>(e))?;
        if res.len() < 2 {
            return Err(TransportError::ResponseTooShort);
        }
        let status = res.split_off(res.len() - 2);
        let code = (status[0] as u16) << 8 | status[1] as u16;
        Ok((res, code.into()))
    }
}

#[derive(Debug, PartialEq)]
pub enum TransportError<T> {
    ResponseTooShort,
    Transport(T),
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use futures_await_test::async_test;

    #[derive(Clone)]
    pub enum MockError {
        _MockNotFound,
    }

    #[derive(Clone)]
    struct Mock {
        result: Result<Vec<u8>, MockError>,
    }
    #[async_trait]
    impl Transport for Mock {
        type Err = MockError;
        async fn exchange(&self, _req: &[u8]) -> Result<Vec<u8>, Self::Err> {
            self.result.clone()
        }
    }
    #[async_test]
    async fn transport_send() {
        let mock = Mock {
            result: Ok(vec![3, 0, 1]),
        };
        if let Ok((res, _)) = mock.send(0x00, 0x00, 0x00, 0x00, &Vec::new()).await {
            assert_eq!(vec![3], res);
        }
    }
}
