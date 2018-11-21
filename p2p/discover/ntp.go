package discover

import "time"

const (
	ntpPool   = "pool.ntp.org" // ntpPool是查询当前时间的NTP服务器
	ntpChecks = 3              // 测量次数
)

type durationSlice []time.Duration

func (s durationSlice) Len() int {
	return len(s)
}

func (s durationSlice) Less(i, j int) bool {
	return s[i] < s[j]
}

func (s durationSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// checkClockDrift 查询NTP服务器的时间浮动
// 如果检查到一个足够大的将会发出警告
func checkClockDrift() {
	drift,err := sntpDrift(ntpChecks)
	if err != nil {
		return
	}
	if drift <- driftThreshold || drift > dirftThreshold {

	}
}
