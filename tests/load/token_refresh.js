import http from 'k6/http';
import { check, sleep, fail } from 'k6';

export const options = {
    stages: [
        { duration: '30s', target: 50 },
        { duration: '1m', target: 500 },
        { duration: '30s', target: 0 },
    ],
    thresholds: {
        http_req_duration: ['p(99)<100'],
    },
};

// Usage:
//   1. Pre-create test users and store their refresh tokens in a file or env vars.
//   2. Run: k6 run --env BASE_URL=http://localhost:8080 --env API_KEY=pk_xxx \
//           --env REFRESH_TOKEN=rt_xxx tests/load/token_refresh.js
//
// For multi-VU testing with unique tokens per VU, export REFRESH_TOKEN_1, REFRESH_TOKEN_2, etc.

export default function () {
    const refreshToken = __ENV[`REFRESH_TOKEN_${__VU}`] || __ENV.REFRESH_TOKEN;
    if (!refreshToken) {
        fail('REFRESH_TOKEN or REFRESH_TOKEN_<VU> env var is required. See usage comments in this file.');
    }

    const res = http.post(`${__ENV.BASE_URL}/auth/token/refresh`, JSON.stringify({
        refresh_token: refreshToken,
    }), {
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': __ENV.API_KEY,
        },
    });
    check(res, {
        'status is 200': (r) => r.status === 200,
        'response time < 100ms': (r) => r.timings.duration < 100,
    });
    sleep(0.1);
}
