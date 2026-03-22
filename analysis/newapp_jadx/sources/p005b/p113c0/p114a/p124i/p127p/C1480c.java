package p005b.p113c0.p114a.p124i.p127p;

import androidx.annotation.NonNull;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/* renamed from: b.c0.a.i.p.c */
/* loaded from: classes2.dex */
public class C1480c implements InterfaceC1478a {

    /* renamed from: a */
    public static final String[] f1470a = new String[0];

    /* renamed from: b */
    public Map<String, Object> f1471b = new ConcurrentHashMap();

    /* renamed from: c */
    public boolean f1472c;

    /* renamed from: d */
    public boolean f1473d;

    @Override // p005b.p113c0.p114a.p124i.p127p.InterfaceC1478a
    /* renamed from: a */
    public boolean mo556a() {
        boolean z;
        if (this.f1473d) {
            z = true;
            this.f1473d = true;
        } else {
            z = false;
        }
        if (z) {
            return this.f1472c;
        }
        throw new IllegalStateException("This session is invalid.");
    }

    /* renamed from: b */
    public void m557b(@NonNull ObjectOutputStream objectOutputStream) {
        objectOutputStream.writeObject(null);
        objectOutputStream.writeLong(0L);
        objectOutputStream.writeLong(0L);
        objectOutputStream.writeInt(-1);
        objectOutputStream.writeBoolean(this.f1472c);
        objectOutputStream.writeBoolean(this.f1473d);
        objectOutputStream.writeInt(this.f1471b.size());
        for (String str : (String[]) this.f1471b.keySet().toArray(f1470a)) {
            Object obj = this.f1471b.get(str);
            if (obj != null && (obj instanceof Serializable)) {
                objectOutputStream.writeObject(str);
                objectOutputStream.writeObject(obj);
            }
        }
    }

    @Override // p005b.p113c0.p114a.p124i.p127p.InterfaceC1478a
    @NonNull
    public String getId() {
        return null;
    }
}
