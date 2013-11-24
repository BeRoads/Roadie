__author__ = 'quentin'

import MySQLdb
import sys
from user_agents import parse
import json

if __name__ == "__main__":
    con = None
    cursor = None
    try:
<<<<<<< HEAD
        con = MySQLdb.connect('localhost', 'root', 'my8na6xe', 'beroads', charset='utf8')
=======
        con = MySQLdb.connect('localhost', 'root', 'cC6GRfysDHyLPH', 'beroads', charset='utf8')
>>>>>>> 07c00e7f5b56fa930df7bb4ed545266fc690c16a
        cursor = con.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT COUNT(*) as total FROM requests")
        total = cursor.fetchone()['total']

        print "Total : %d"%total
<<<<<<< HEAD
        f = 0
        t = 30
=======
        f = 80000
        t = 81000
>>>>>>> 07c00e7f5b56fa930df7bb4ed545266fc690c16a
        while t < total:
            query = "SELECT * FROM requests LIMIT %d, %d;"%(f,t)
            print query
            cursor.execute(query)
            requests = cursor.fetchall()
            for request in requests:
                user_agent = parse(request['user_agent'])
                update_query = "UPDATE requests SET browser = '%s', os = '%s', device = '%s' WHERE id = %d"%(user_agent.browser.family, user_agent.os.family, user_agent.device.family, request['id'])
                cursor.execute(update_query)
<<<<<<< HEAD
            f+=30
            t+=30
=======
            f+=1000
            t+=1000
>>>>>>> 07c00e7f5b56fa930df7bb4ed545266fc690c16a

    except KeyboardInterrupt:
        if con:
            if cursor:
                cursor.close()
            con.close()
        sys.exit(2)
    except MySQLdb.Error as e:
        print e.message
        if con:
            if cursor:
                cursor.close()
            con.close()
        sys.exit(2)
    except Exception as e:
        print e.message
        if con:
<<<<<<< HEAD
            con.close()
=======
            con.close()
>>>>>>> 07c00e7f5b56fa930df7bb4ed545266fc690c16a
