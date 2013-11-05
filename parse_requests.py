__author__ = 'quentin'

import MySQLdb
import sys
from user_agents import parse
import json

if __name__ == "__main__":
    con = None
    cursor = None
    try:
        con = MySQLdb.connect('localhost', 'root', 'cC6GRfysDHyLPH', 'beroads', charset='utf8')
        cursor = con.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT COUNT(*) as total FROM requests")
        total = cursor.fetchone()['total']

        print "Total : %d"%total
        f = 80000
        t = 81000
        while t < total:
            query = "SELECT * FROM requests LIMIT %d, %d;"%(f,t)
            print query
            cursor.execute(query)
            requests = cursor.fetchall()
            for request in requests:
                user_agent = parse(request['user_agent'])
                update_query = "UPDATE requests SET browser = '%s', os = '%s', device = '%s' WHERE id = %d"%(user_agent.browser.family, user_agent.os.family, user_agent.device.family, request['id'])
                cursor.execute(update_query)
            f+=1000
            t+=1000

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
            con.close()
