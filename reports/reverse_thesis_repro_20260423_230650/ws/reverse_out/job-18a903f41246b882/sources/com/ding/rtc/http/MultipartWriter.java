package com.ding.rtc.http;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

/* JADX INFO: loaded from: classes.dex */
public interface MultipartWriter {
    void addPart(PrintWriter printWriter, OutputStream outputStream) throws IOException;
}
