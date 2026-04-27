package L0;

import N0.j;
import X.k;
import X.p;
import a0.C0221g;
import a0.InterfaceC0215a;
import f0.AbstractC0526d;
import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: loaded from: classes.dex */
public class f {

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f1710g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final InterfaceC0215a f1711h;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f1706c = 0;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f1705b = 0;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f1707d = 0;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f1709f = 0;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f1708e = 0;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f1704a = 0;

    public f(InterfaceC0215a interfaceC0215a) {
        this.f1711h = (InterfaceC0215a) k.g(interfaceC0215a);
    }

    private boolean a(InputStream inputStream) throws Throwable {
        int i3;
        int i4 = this.f1708e;
        while (this.f1704a != 6 && (i3 = inputStream.read()) != -1) {
            try {
                int i5 = this.f1706c;
                this.f1706c = i5 + 1;
                if (this.f1710g) {
                    this.f1704a = 6;
                    this.f1710g = false;
                    return false;
                }
                int i6 = this.f1704a;
                if (i6 != 0) {
                    if (i6 != 1) {
                        if (i6 != 2) {
                            if (i6 != 3) {
                                if (i6 == 4) {
                                    this.f1704a = 5;
                                } else if (i6 != 5) {
                                    k.i(false);
                                } else {
                                    int i7 = ((this.f1705b << 8) + i3) - 2;
                                    AbstractC0526d.a(inputStream, i7);
                                    this.f1706c += i7;
                                    this.f1704a = 2;
                                }
                            } else if (i3 == 255) {
                                this.f1704a = 3;
                            } else if (i3 == 0) {
                                this.f1704a = 2;
                            } else if (i3 == 217) {
                                this.f1710g = true;
                                f(i5 - 1);
                                this.f1704a = 2;
                            } else {
                                if (i3 == 218) {
                                    f(i5 - 1);
                                }
                                if (b(i3)) {
                                    this.f1704a = 4;
                                } else {
                                    this.f1704a = 2;
                                }
                            }
                        } else if (i3 == 255) {
                            this.f1704a = 3;
                        }
                    } else if (i3 == 216) {
                        this.f1704a = 2;
                    } else {
                        this.f1704a = 6;
                    }
                } else if (i3 == 255) {
                    this.f1704a = 1;
                } else {
                    this.f1704a = 6;
                }
                this.f1705b = i3;
            } catch (IOException e3) {
                p.a(e3);
            }
            return (this.f1704a == 6 || this.f1708e == i4) ? false : true;
        }
        if (this.f1704a == 6) {
            return false;
        }
    }

    private static boolean b(int i3) {
        if (i3 == 1) {
            return false;
        }
        return ((i3 >= 208 && i3 <= 215) || i3 == 217 || i3 == 216) ? false : true;
    }

    private void f(int i3) {
        int i4 = this.f1707d;
        if (i4 > 0) {
            this.f1709f = i3;
        }
        this.f1707d = i4 + 1;
        this.f1708e = i4;
    }

    public int c() {
        return this.f1709f;
    }

    public int d() {
        return this.f1708e;
    }

    public boolean e() {
        return this.f1710g;
    }

    public boolean g(j jVar) {
        if (this.f1704a == 6 || jVar.d0() <= this.f1706c) {
            return false;
        }
        C0221g c0221g = new C0221g(jVar.W(), (byte[]) this.f1711h.get(16384), this.f1711h);
        try {
            AbstractC0526d.a(c0221g, this.f1706c);
            return a(c0221g);
        } catch (IOException e3) {
            p.a(e3);
            return false;
        } finally {
            X.b.b(c0221g);
        }
    }
}
