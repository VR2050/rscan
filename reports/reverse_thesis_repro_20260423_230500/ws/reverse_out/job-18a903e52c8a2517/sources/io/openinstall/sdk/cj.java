package io.openinstall.sdk;

import com.snail.antifake.deviceid.ShellAdbUtils;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class cj {
    private String a(InputStream inputStream) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream, bu.c));
        StringBuilder sb = new StringBuilder();
        while (true) {
            String line = bufferedReader.readLine();
            if (line == null) {
                String string = sb.toString();
                bufferedReader.close();
                return string;
            }
            sb.append(line);
            sb.append(ShellAdbUtils.COMMAND_LINE_END);
        }
    }

    private void a(HttpURLConnection httpURLConnection, byte[] bArr) throws IOException {
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(httpURLConnection.getOutputStream());
        bufferedOutputStream.write(bArr);
        bufferedOutputStream.flush();
        bufferedOutputStream.close();
    }

    public cr a(cm cmVar, int i) throws Throwable {
        HttpURLConnection httpURLConnection;
        String strB = cmVar.b();
        if (cmVar.c() != null) {
            strB = strB + "?" + cmVar.c();
        }
        if (i < 1000) {
            i = 1000;
        }
        if (i > 10000) {
            i = 10000;
        }
        boolean z = cmVar.a() == cl.POST && cmVar.d() != null;
        HttpURLConnection httpURLConnection2 = null;
        try {
            try {
                httpURLConnection = (HttpURLConnection) new URL(strB).openConnection();
            } catch (Exception e) {
                e = e;
            }
        } catch (Throwable th) {
            th = th;
        }
        try {
            httpURLConnection.setRequestMethod(cmVar.a().name());
            httpURLConnection.setDoInput(true);
            httpURLConnection.setUseCaches(false);
            httpURLConnection.setConnectTimeout(i);
            httpURLConnection.setReadTimeout(i);
            if (z) {
                httpURLConnection.setDoOutput(true);
                httpURLConnection.setFixedLengthStreamingMode(cmVar.d().length);
            }
            if (cmVar.e() != null) {
                for (Map.Entry<String, String> entry : cmVar.e().entrySet()) {
                    httpURLConnection.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }
            httpURLConnection.setRequestProperty("Connection", "close");
            System.currentTimeMillis();
            httpURLConnection.connect();
            if (z) {
                a(httpURLConnection, cmVar.d());
            }
            if (httpURLConnection.getResponseCode() == 200) {
                cr crVar = new cr(a(httpURLConnection.getInputStream()));
                if (httpURLConnection != null) {
                    httpURLConnection.disconnect();
                }
                return crVar;
            }
            cr crVar2 = new cr(httpURLConnection.getResponseCode(), httpURLConnection.getResponseMessage());
            if (httpURLConnection != null) {
                httpURLConnection.disconnect();
            }
            return crVar2;
        } catch (Exception e2) {
            e = e2;
            httpURLConnection2 = httpURLConnection;
            cr crVar3 = new cr(e);
            if (httpURLConnection2 != null) {
                httpURLConnection2.disconnect();
            }
            return crVar3;
        } catch (Throwable th2) {
            th = th2;
            httpURLConnection2 = httpURLConnection;
            if (httpURLConnection2 != null) {
                httpURLConnection2.disconnect();
            }
            throw th;
        }
    }
}
