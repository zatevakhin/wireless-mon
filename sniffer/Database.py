# -*- coding: utf-8 -*-

import sqlite3


CREATE_HANDSHAKE_TABLE = """
    CREATE TABLE IF NOT EXISTS Handshake (
        id        INTEGER PRIMARY KEY NOT NULL,
        ap_mac    CHAR(17)            NOT NULL,
        cl_mac    CHAR(17)            NOT NULL,
        beacon    BLOB                NOT NULL,
        one       BLOB                NOT NULL,
        two       BLOB                NOT NULL,
        three     BLOB                NOT NULL,
        four      BLOB                NOT NULL,
        t_stamp   TIMESTAMP DEFAULT   CURRENT_TIMESTAMP,

        UNIQUE(ap_mac, cl_mac)
    );
"""

class Database(object):
    
    def __init__(self, db_name):
        self.db_name = db_name

        with self.connect() as connection:
            c = connection.cursor()
            c.execute(CREATE_HANDSHAKE_TABLE)

    def connect(self):
        connection = sqlite3.connect(self.db_name)
        connection.row_factory = Database.dict_factory

        connection.text_factory = str

        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute("PRAGMA encoding = 'UTF-8';")

        return connection

    @staticmethod
    def dict_factory(cursor, row):
        return {col[0]: row[idx] for (idx, col) in enumerate(cursor.description)}
