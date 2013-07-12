Ext.require('Ext.chart.*');
Ext.require(['Ext.fx.target.Sprite']);

Ext.onReady(function () {
    store1.loadData(generateData(8));

    var line = new Ext.chart.Chart({
                                       width: 600,
                                       height: 300,
                                       hidden: false,
                                       maximizable: true,
                                       title: 'Line Chart',
                                       renderTo: Ext.get('hits_line'),

                                       style: 'background:#fff',
                                       animate: true,
                                       store: store1,
                                       shadow: true,
                                       theme: 'Category1',
                                       legend: {
                                           position: 'right'
                                       },
                                       axes: [
                                           {
                                               type: 'Numeric',
                                               minimum: 0,
                                               position: 'left',
                                               fields: ['data1'],
                                               title: 'Number of Hits',
                                               minorTickSteps: 1,
                                               grid: {
                                                   odd: {
                                                       opacity: 1,
                                                       fill: '#ddd',
                                                       stroke: '#bbb',
                                                       'stroke-width': 0.5
                                                   }
                                               }
                                           },
                                           {
                                               type: 'Category',
                                               position: 'bottom',
                                               fields: ['name'],
                                               title: 'Month of the Year'
                                           }
                                       ],
                                       series: [
                                           {
                                               type: 'line',
                                               highlight: {
                                                   size: 7,
                                                   radius: 7
                                               },
                                               axis: 'left',
                                               xField: 'name',
                                               yField: 'data1',
                                               markerConfig: {
                                                   type: 'cross',
                                                   size: 4,
                                                   radius: 4,
                                                   'stroke-width': 0
                                               }
                                           }
                                       ]
                                   });
});
