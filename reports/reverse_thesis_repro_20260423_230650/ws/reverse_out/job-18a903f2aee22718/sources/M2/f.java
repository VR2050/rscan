package M2;

import java.util.logging.Handler;
import java.util.logging.LogRecord;

/* JADX INFO: loaded from: classes.dex */
public final class f extends Handler {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final f f1815a = new f();

    private f() {
    }

    @Override // java.util.logging.Handler
    public void publish(LogRecord logRecord) {
        t2.j.f(logRecord, "record");
        e eVar = e.f1814c;
        String loggerName = logRecord.getLoggerName();
        t2.j.e(loggerName, "record.loggerName");
        int iB = g.b(logRecord);
        String message = logRecord.getMessage();
        t2.j.e(message, "record.message");
        eVar.a(loggerName, iB, message, logRecord.getThrown());
    }

    @Override // java.util.logging.Handler
    public void close() {
    }

    @Override // java.util.logging.Handler
    public void flush() {
    }
}
