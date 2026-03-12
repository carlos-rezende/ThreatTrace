/**
 * Chart.js campaign timeline
 */
let timelineChartInstance = null;

function renderTimelineChart(canvasId, timelineData) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return;

    if (timelineChartInstance) {
        timelineChartInstance.destroy();
        timelineChartInstance = null;
    }

    const chartData = timelineData?.chart_data;
    if (!chartData?.labels?.length) return;

    timelineChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: chartData.labels,
            datasets: (chartData.datasets || []).map((ds, i) => ({
                ...ds,
                backgroundColor: 'rgba(77, 163, 255, 0.6)',
                borderColor: '#4da3ff',
                borderWidth: 1,
            })),
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(77, 163, 255, 0.1)' },
                    ticks: { color: '#9fb3d1' },
                },
                x: {
                    grid: { color: 'rgba(77, 163, 255, 0.1)' },
                    ticks: { color: '#9fb3d1', maxRotation: 45 },
                },
            },
        },
    });
}
