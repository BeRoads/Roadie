Ext.onReady(function () {
    var donut = false,
        chart;
    function refresh() {
        var series = chart.series.items,
            len = series.length;

        for (var i = 0; i < len; i++) {
            s = series[i];
            s.donut = donut;
        }
        chart.redraw();
    }

    store1.loadData(generateDataUA(5));


    chart = new Ext.chart.Chart({
        width: 400,
        height: 300,
        hidden: false,
        maximizable: true,
        animate: true,
        store: storeUA,
        renderTo: Ext.get('user_agents_pie'),
        shadow: true,
        legend: {
            position: 'right'
        },
        theme: 'Base:gradients',
        series: [{
            type: 'pie',
            field: 'data1',
            showInLegend: true,
            highlight: {
              segment: {
                margin: 20
              }
            },
            label: {
                field: 'name',
                display: 'rotate',
                contrast: true,
                font: '12px "Lucida Grande", "Lucida Sans Unicode", Verdana, Arial, Helvetica, sans-serif'
            },
            animate: true
        }]
    });
});