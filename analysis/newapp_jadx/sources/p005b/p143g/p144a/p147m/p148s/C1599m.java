package p005b.p143g.p144a.p147m.p148s;

import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import java.io.IOException;
import java.util.Objects;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1591e;

/* renamed from: b.g.a.m.s.m */
/* loaded from: classes.dex */
public final class C1599m implements InterfaceC1591e<ParcelFileDescriptor> {

    /* renamed from: a */
    public final b f2025a;

    @RequiresApi(21)
    /* renamed from: b.g.a.m.s.m$a */
    public static final class a implements InterfaceC1591e.a<ParcelFileDescriptor> {
        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e.a
        @NonNull
        /* renamed from: a */
        public Class<ParcelFileDescriptor> mo843a() {
            return ParcelFileDescriptor.class;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e.a
        @NonNull
        /* renamed from: b */
        public InterfaceC1591e<ParcelFileDescriptor> mo844b(@NonNull ParcelFileDescriptor parcelFileDescriptor) {
            return new C1599m(parcelFileDescriptor);
        }
    }

    @RequiresApi(21)
    /* renamed from: b.g.a.m.s.m$b */
    public static final class b {

        /* renamed from: a */
        public final ParcelFileDescriptor f2026a;

        public b(ParcelFileDescriptor parcelFileDescriptor) {
            this.f2026a = parcelFileDescriptor;
        }
    }

    @RequiresApi(21)
    public C1599m(ParcelFileDescriptor parcelFileDescriptor) {
        this.f2025a = new b(parcelFileDescriptor);
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e
    /* renamed from: b */
    public void mo842b() {
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e
    @NonNull
    @RequiresApi(21)
    /* renamed from: c, reason: merged with bridge method [inline-methods] */
    public ParcelFileDescriptor mo841a() {
        b bVar = this.f2025a;
        Objects.requireNonNull(bVar);
        try {
            Os.lseek(bVar.f2026a.getFileDescriptor(), 0L, OsConstants.SEEK_SET);
            return bVar.f2026a;
        } catch (ErrnoException e2) {
            throw new IOException(e2);
        }
    }
}
