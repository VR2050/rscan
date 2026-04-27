package P0;

import java.util.Map;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public abstract class a implements e {
    @Override // com.facebook.imagepipeline.producers.h0
    public boolean c(String str) {
        j.f(str, "requestId");
        return false;
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public void e(String str, String str2, String str3) {
        j.f(str, "requestId");
        j.f(str2, "producerName");
        j.f(str3, "eventName");
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public void f(String str, String str2, Map map) {
        j.f(str, "requestId");
        j.f(str2, "producerName");
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public void g(String str, String str2) {
        j.f(str, "requestId");
        j.f(str2, "producerName");
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public void h(String str, String str2, Throwable th, Map map) {
        j.f(str, "requestId");
        j.f(str2, "producerName");
        j.f(th, "t");
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public void i(String str, String str2, Map map) {
        j.f(str, "requestId");
        j.f(str2, "producerName");
    }

    @Override // com.facebook.imagepipeline.producers.h0
    public void k(String str, String str2, boolean z3) {
        j.f(str, "requestId");
        j.f(str2, "producerName");
    }
}
