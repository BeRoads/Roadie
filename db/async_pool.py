import asyncio
from concurrent.futures import ThreadPoolExecutor

import pymysql
from pymysql.cursors import DictCursor


class QueryResult(object):
    """Cursor-like wrapper kept for compatibility with legacy handlers."""

    def __init__(self, rows, rowcount=0, lastrowid=None):
        self._rows = rows or []
        self.rowcount = rowcount
        self.lastrowid = lastrowid

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)

    def __len__(self):
        return len(self._rows)

    def __bool__(self):
        return bool(self._rows)

    __nonzero__ = __bool__


class AsyncPyMySQLPool(object):
    """Minimal async DB facade that mirrors the old tornado_mysql.execute API."""

    def __init__(
        self,
        host,
        port,
        database,
        user,
        password,
        max_workers=4,
        charset="utf8mb4",
    ):
        self._dsn = {
            "host": host,
            "port": int(port),
            "database": database,
            "user": user,
            "password": password,
            "cursorclass": DictCursor,
            "autocommit": True,
            "charset": charset,
        }
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

    def _execute_sync(self, query, params):
        conn = pymysql.connect(**self._dsn)
        try:
            with conn.cursor() as cursor:
                cursor.execute(query, params or ())
                if cursor.description:
                    rows = cursor.fetchall()
                else:
                    rows = []
                return QueryResult(rows, rowcount=cursor.rowcount, lastrowid=cursor.lastrowid)
        finally:
            conn.close()

    async def execute(self, query, *params):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._execute_sync, query, params)

    def close(self):
        self._executor.shutdown(wait=False)

