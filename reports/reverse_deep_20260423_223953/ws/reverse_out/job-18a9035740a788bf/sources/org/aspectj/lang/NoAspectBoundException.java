package org.aspectj.lang;

/* JADX INFO: loaded from: classes3.dex */
public class NoAspectBoundException extends RuntimeException {
    Throwable cause;

    /* JADX WARN: Illegal instructions before constructor call */
    public NoAspectBoundException(String aspectName, Throwable inner) {
        String string;
        if (inner == null) {
            string = aspectName;
        } else {
            StringBuffer stringBuffer = new StringBuffer();
            stringBuffer.append("Exception while initializing ");
            stringBuffer.append(aspectName);
            stringBuffer.append(": ");
            stringBuffer.append(inner);
            string = stringBuffer.toString();
        }
        super(string);
        this.cause = inner;
    }

    public NoAspectBoundException() {
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.cause;
    }
}
