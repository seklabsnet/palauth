package admin

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectAnalytics_JSON(t *testing.T) {
	analytics := &ProjectAnalytics{
		MAU:            100,
		ActiveSessions: 50,
		TotalUsers:     200,
		LoginTrend24h:  42,
	}

	data, err := json.Marshal(analytics)
	require.NoError(t, err)

	var result map[string]any
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, float64(100), result["mau"])
	assert.Equal(t, float64(50), result["active_sessions"])
	assert.Equal(t, float64(200), result["total_users"])
	assert.Equal(t, float64(42), result["login_trend_24h"])
}
