package p458k.p459p0.p466j;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.logging.Logger;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p474l.C4754p;
import p474l.InterfaceC4762x;
import p474l.InterfaceC4764z;

/* renamed from: k.p0.j.b */
/* loaded from: classes3.dex */
public interface InterfaceC4456b {

    /* renamed from: a */
    @JvmField
    @NotNull
    public static final InterfaceC4456b f11958a = new InterfaceC4456b() { // from class: k.p0.j.a$a
        @Override // p458k.p459p0.p466j.InterfaceC4456b
        @NotNull
        /* renamed from: a */
        public InterfaceC4764z mo5224a(@NotNull File file) {
            Intrinsics.checkParameterIsNotNull(file, "file");
            return C2354n.m2394G1(file);
        }

        @Override // p458k.p459p0.p466j.InterfaceC4456b
        @NotNull
        /* renamed from: b */
        public InterfaceC4762x mo5225b(@NotNull File file) {
            Intrinsics.checkParameterIsNotNull(file, "file");
            try {
                return C2354n.m2391F1(file, false, 1, null);
            } catch (FileNotFoundException unused) {
                file.getParentFile().mkdirs();
                return C2354n.m2391F1(file, false, 1, null);
            }
        }

        @Override // p458k.p459p0.p466j.InterfaceC4456b
        /* renamed from: c */
        public void mo5226c(@NotNull File directory) {
            Intrinsics.checkParameterIsNotNull(directory, "directory");
            File[] listFiles = directory.listFiles();
            if (listFiles == null) {
                throw new IOException(C1499a.m634t("not a readable directory: ", directory));
            }
            for (File file : listFiles) {
                Intrinsics.checkExpressionValueIsNotNull(file, "file");
                if (file.isDirectory()) {
                    mo5226c(file);
                }
                if (!file.delete()) {
                    throw new IOException(C1499a.m634t("failed to delete ", file));
                }
            }
        }

        @Override // p458k.p459p0.p466j.InterfaceC4456b
        /* renamed from: d */
        public boolean mo5227d(@NotNull File file) {
            Intrinsics.checkParameterIsNotNull(file, "file");
            return file.exists();
        }

        @Override // p458k.p459p0.p466j.InterfaceC4456b
        /* renamed from: e */
        public void mo5228e(@NotNull File from, @NotNull File to) {
            Intrinsics.checkParameterIsNotNull(from, "from");
            Intrinsics.checkParameterIsNotNull(to, "to");
            mo5229f(to);
            if (from.renameTo(to)) {
                return;
            }
            throw new IOException("failed to rename " + from + " to " + to);
        }

        @Override // p458k.p459p0.p466j.InterfaceC4456b
        /* renamed from: f */
        public void mo5229f(@NotNull File file) {
            Intrinsics.checkParameterIsNotNull(file, "file");
            if (!file.delete() && file.exists()) {
                throw new IOException(C1499a.m634t("failed to delete ", file));
            }
        }

        @Override // p458k.p459p0.p466j.InterfaceC4456b
        @NotNull
        /* renamed from: g */
        public InterfaceC4762x mo5230g(@NotNull File appendingSink) {
            Intrinsics.checkParameterIsNotNull(appendingSink, "file");
            try {
                Logger logger = C4754p.f12154a;
                Intrinsics.checkNotNullParameter(appendingSink, "$this$appendingSink");
                return C2354n.m2385D1(new FileOutputStream(appendingSink, true));
            } catch (FileNotFoundException unused) {
                appendingSink.getParentFile().mkdirs();
                Logger logger2 = C4754p.f12154a;
                Intrinsics.checkNotNullParameter(appendingSink, "$this$appendingSink");
                return C2354n.m2385D1(new FileOutputStream(appendingSink, true));
            }
        }

        @Override // p458k.p459p0.p466j.InterfaceC4456b
        /* renamed from: h */
        public long mo5231h(@NotNull File file) {
            Intrinsics.checkParameterIsNotNull(file, "file");
            return file.length();
        }
    };

    @NotNull
    /* renamed from: a */
    InterfaceC4764z mo5224a(@NotNull File file);

    @NotNull
    /* renamed from: b */
    InterfaceC4762x mo5225b(@NotNull File file);

    /* renamed from: c */
    void mo5226c(@NotNull File file);

    /* renamed from: d */
    boolean mo5227d(@NotNull File file);

    /* renamed from: e */
    void mo5228e(@NotNull File file, @NotNull File file2);

    /* renamed from: f */
    void mo5229f(@NotNull File file);

    @NotNull
    /* renamed from: g */
    InterfaceC4762x mo5230g(@NotNull File file);

    /* renamed from: h */
    long mo5231h(@NotNull File file);
}
