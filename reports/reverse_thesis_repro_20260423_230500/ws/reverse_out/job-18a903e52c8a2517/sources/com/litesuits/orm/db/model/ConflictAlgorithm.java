package com.litesuits.orm.db.model;

/* JADX INFO: loaded from: classes3.dex */
public enum ConflictAlgorithm {
    None(" "),
    Rollback(" OR ROLLBACK "),
    Abort(" OR ABORT "),
    Fail(" OR FAIL "),
    Ignore(" OR IGNORE "),
    Replace(" OR REPLACE ");

    private String algorithm;

    ConflictAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return this.algorithm;
    }
}
