package com.facebook.hermes.intl;

import android.icu.text.RuleBasedCollator;
import com.facebook.hermes.intl.a;

/* JADX INFO: loaded from: classes.dex */
public class h implements com.facebook.hermes.intl.a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private RuleBasedCollator f6030a = null;

    static /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f6031a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        static final /* synthetic */ int[] f6032b;

        static {
            int[] iArr = new int[a.b.values().length];
            f6032b = iArr;
            try {
                iArr[a.b.UPPER.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f6032b[a.b.LOWER.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f6032b[a.b.FALSE.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            int[] iArr2 = new int[a.c.values().length];
            f6031a = iArr2;
            try {
                iArr2[a.c.BASE.ordinal()] = 1;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                f6031a[a.c.ACCENT.ordinal()] = 2;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                f6031a[a.c.CASE.ordinal()] = 3;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                f6031a[a.c.VARIANT.ordinal()] = 4;
            } catch (NoSuchFieldError unused7) {
            }
        }
    }

    h() {
    }

    @Override // com.facebook.hermes.intl.a
    public com.facebook.hermes.intl.a a(a.b bVar) {
        int i3 = a.f6032b[bVar.ordinal()];
        if (i3 == 1) {
            this.f6030a.setUpperCaseFirst(true);
        } else if (i3 != 2) {
            this.f6030a.setCaseFirstDefault();
        } else {
            this.f6030a.setLowerCaseFirst(true);
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.a
    public com.facebook.hermes.intl.a b(boolean z3) {
        if (z3) {
            this.f6030a.setNumericCollation(A0.d.e(Boolean.TRUE));
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.a
    public int c(String str, String str2) {
        return this.f6030a.compare(str, str2);
    }

    @Override // com.facebook.hermes.intl.a
    public com.facebook.hermes.intl.a d(a.c cVar) {
        int i3 = a.f6031a[cVar.ordinal()];
        if (i3 == 1) {
            this.f6030a.setStrength(0);
        } else if (i3 == 2) {
            this.f6030a.setStrength(1);
        } else if (i3 == 3) {
            this.f6030a.setStrength(0);
            this.f6030a.setCaseLevel(true);
        } else if (i3 == 4) {
            this.f6030a.setStrength(2);
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.a
    public a.c e() {
        RuleBasedCollator ruleBasedCollator = this.f6030a;
        if (ruleBasedCollator == null) {
            return a.c.LOCALE;
        }
        int strength = ruleBasedCollator.getStrength();
        return strength == 0 ? this.f6030a.isCaseLevel() ? a.c.CASE : a.c.BASE : strength == 1 ? a.c.ACCENT : a.c.VARIANT;
    }

    @Override // com.facebook.hermes.intl.a
    public com.facebook.hermes.intl.a f(A0.b bVar) {
        RuleBasedCollator ruleBasedCollator = (RuleBasedCollator) android.icu.text.Collator.getInstance(((A0.g) bVar).h());
        this.f6030a = ruleBasedCollator;
        ruleBasedCollator.setDecomposition(17);
        return this;
    }

    @Override // com.facebook.hermes.intl.a
    public com.facebook.hermes.intl.a g(boolean z3) {
        if (z3) {
            this.f6030a.setAlternateHandlingShifted(true);
        }
        return this;
    }
}
