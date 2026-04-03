import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
    stages: [
        { duration: '30s', target: 100 },
        { duration: '1m', target: 1000 },
        { duration: '30s', target: 0 },
    ],
    thresholds: {
        http_req_duration: ['p(99)<500'],
    },
};

export default function () {
    const res = http.post(`${__ENV.BASE_URL}/auth/login`, JSON.stringify({
        email: `user${__VU}@test.com`,
        password: 'test-password-secure-123',
    }), {
        headers: {
            'Content-Type': 'application/json',
            'X-API-Key': __ENV.API_KEY,
        },
    });
    check(res, {
        'status is 200 or 401': (r) => r.status === 200 || r.status === 401,
        'response time < 500ms': (r) => r.timings.duration < 500,
    });
    sleep(0.1);
}
