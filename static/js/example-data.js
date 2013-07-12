var userAgents = ['Firefox', 'Chrome', 'iOS', 'Android', 'Opera', 'FirefoxOS', 'Bada', 'WP7', 'WP8', 'Symbian'];
var languages = ['fr','nl','de','en'];
function generateDataUA(n) {
    var data = [],
        p = (Math.random() * 11) + 1,
        i;
    for (i = 0; i < (n || 12); i++) {
        data.push({
                      name: userAgents[i],
                      data1: Math.floor(Math.max((Math.random() * 100), 20)),
                      data2: Math.floor(Math.max((Math.random() * 100), 20)),
                      data3: Math.floor(Math.max((Math.random() * 100), 20)),
                      data4: Math.floor(Math.max((Math.random() * 100), 20)),
                      data5: Math.floor(Math.max((Math.random() * 100), 20)),
                      data6: Math.floor(Math.max((Math.random() * 100), 20)),
                      data7: Math.floor(Math.max((Math.random() * 100), 20)),
                      data8: Math.floor(Math.max((Math.random() * 100), 20)),
                      data9: Math.floor(Math.max((Math.random() * 100), 20))
                  });
    }
    return data;
}

function generateDataLang(n) {
    var data = [],
        p = (Math.random() * 11) + 1,
        i;
    for (i = 0; i < 4; i++) {
        data.push({
                      name: languages[i],
                      data1: Math.floor(Math.max((Math.random() * 100), 20)),
                      data2: Math.floor(Math.max((Math.random() * 100), 20)),
                      data3: Math.floor(Math.max((Math.random() * 100), 20)),
                      data4: Math.floor(Math.max((Math.random() * 100), 20)),
                      data5: Math.floor(Math.max((Math.random() * 100), 20)),
                      data6: Math.floor(Math.max((Math.random() * 100), 20)),
                      data7: Math.floor(Math.max((Math.random() * 100), 20)),
                      data8: Math.floor(Math.max((Math.random() * 100), 20)),
                      data9: Math.floor(Math.max((Math.random() * 100), 20))
                  });
    }
    return data;
}


function generateData(n, floor) {
    var data = [],
        p = (Math.random() * 11) + 1,
        i;

    floor = (!floor && floor !== 0) ? 20 : floor;

    for (i = 0; i < (n || 12); i++) {
        data.push({
                      name: Ext.Date.monthNames[i % 12],
                      data1: Math.floor(Math.max((Math.random() * 100), floor)),
                      data2: Math.floor(Math.max((Math.random() * 100), floor)),
                      data3: Math.floor(Math.max((Math.random() * 100), floor)),
                      data4: Math.floor(Math.max((Math.random() * 100), floor)),
                      data5: Math.floor(Math.max((Math.random() * 100), floor)),
                      data6: Math.floor(Math.max((Math.random() * 100), floor)),
                      data7: Math.floor(Math.max((Math.random() * 100), floor)),
                      data8: Math.floor(Math.max((Math.random() * 100), floor)),
                      data9: Math.floor(Math.max((Math.random() * 100), floor))
                  });
    }
    return data;
}


function generateDataNegative(n, floor) {
    var data = [],
        p = (Math.random() * 11) + 1,
        i;

    floor = (!floor && floor !== 0) ? 20 : floor;

    for (i = 0; i < (n || 12); i++) {
        data.push({
                      name: Ext.Date.monthNames[i % 12],
                      data1: Math.floor(((Math.random() - 0.5) * 100), floor),
                      data2: Math.floor(((Math.random() - 0.5) * 100), floor),
                      data3: Math.floor(((Math.random() - 0.5) * 100), floor),
                      data4: Math.floor(((Math.random() - 0.5) * 100), floor),
                      data5: Math.floor(((Math.random() - 0.5) * 100), floor),
                      data6: Math.floor(((Math.random() - 0.5) * 100), floor),
                      data7: Math.floor(((Math.random() - 0.5) * 100), floor),
                      data8: Math.floor(((Math.random() - 0.5) * 100), floor),
                      data9: Math.floor(((Math.random() - 0.5) * 100), floor)
                  });
    }
    return data;
}

var store1 = new Ext.data.JsonStore({
                                        fields: ['name', 'data1', 'data2', 'data3', 'data4', 'data5', 'data6', 'data7', 'data9', 'data9'],
                                        data: generateData()
                                    });
var storeUA = new Ext.data.JsonStore({
                                                fields: ['name', 'data1', 'data2', 'data3', 'data4', 'data5', 'data6', 'data7', 'data9', 'data9'],
                                                data: generateDataUA(4)
                                            });
var storeLanguages = new Ext.data.JsonStore({
                                        fields: ['name', 'data1', 'data2', 'data3', 'data4', 'data5', 'data6', 'data7', 'data9', 'data9'],
                                        data: generateDataLang(4)
                                    });