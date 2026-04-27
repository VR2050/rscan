package com.facebook.hermes.intl;

import android.icu.text.CompactDecimalFormat;
import android.icu.text.DecimalFormat;
import android.icu.text.DecimalFormatSymbols;
import android.icu.text.MeasureFormat;
import android.icu.text.NumberFormat;
import android.icu.text.NumberingSystem;
import android.icu.util.Currency;
import android.icu.util.Measure;
import android.icu.util.MeasureUnit;
import android.icu.util.ULocale;
import android.os.Build;
import com.facebook.hermes.intl.c;
import java.text.AttributedCharacterIterator;
import java.text.Format;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes.dex */
public class j implements c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Format f6036a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private android.icu.text.NumberFormat f6037b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private A0.g f6038c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private c.h f6039d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private MeasureUnit f6040e;

    static /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f6041a;

        static {
            int[] iArr = new int[c.g.values().length];
            f6041a = iArr;
            try {
                iArr[c.g.NEVER.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f6041a[c.g.ALWAYS.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f6041a[c.g.EXCEPTZERO.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    j() {
    }

    public static int n(String str) throws A0.e {
        try {
            return Currency.getInstance(str).getDefaultFractionDigits();
        } catch (IllegalArgumentException unused) {
            throw new A0.e("Invalid currency code !");
        }
    }

    private void o(android.icu.text.NumberFormat numberFormat, A0.b bVar, c.h hVar) {
        this.f6037b = numberFormat;
        this.f6036a = numberFormat;
        this.f6038c = (A0.g) bVar;
        this.f6039d = hVar;
        numberFormat.setRoundingMode(4);
    }

    private static MeasureUnit p(String str) throws A0.e {
        for (MeasureUnit measureUnit : MeasureUnit.getAvailable()) {
            if (!measureUnit.getSubtype().equals(str)) {
                if (measureUnit.getSubtype().equals(measureUnit.getType() + "-" + str)) {
                }
            }
            return measureUnit;
        }
        throw new A0.e("Unknown unit: " + str);
    }

    @Override // com.facebook.hermes.intl.c
    public AttributedCharacterIterator a(double d3) {
        try {
            try {
                Format format = this.f6036a;
                return (!(format instanceof MeasureFormat) || this.f6040e == null) ? format.formatToCharacterIterator(Double.valueOf(d3)) : format.formatToCharacterIterator(new Measure(Double.valueOf(d3), this.f6040e));
            } catch (RuntimeException unused) {
                return android.icu.text.NumberFormat.getInstance(ULocale.forLanguageTag("en")).formatToCharacterIterator(Double.valueOf(d3));
            }
        } catch (NumberFormatException unused2) {
            return android.icu.text.NumberFormat.getInstance(ULocale.getDefault()).formatToCharacterIterator(Double.valueOf(d3));
        } catch (Exception unused3) {
            return android.icu.text.NumberFormat.getInstance(ULocale.forLanguageTag("en")).formatToCharacterIterator(Double.valueOf(d3));
        }
    }

    @Override // com.facebook.hermes.intl.c
    public String b(double d3) {
        try {
            try {
                Format format = this.f6036a;
                return (!(format instanceof MeasureFormat) || this.f6040e == null) ? format.format(Double.valueOf(d3)) : format.format(new Measure(Double.valueOf(d3), this.f6040e));
            } catch (NumberFormatException unused) {
                return android.icu.text.NumberFormat.getInstance(ULocale.getDefault()).format(d3);
            }
        } catch (RuntimeException unused2) {
            return android.icu.text.NumberFormat.getInstance(ULocale.forLanguageTag("en")).format(d3);
        }
    }

    @Override // com.facebook.hermes.intl.c
    public String c(A0.b bVar) {
        return NumberingSystem.getInstance((ULocale) bVar.h()).getName();
    }

    @Override // com.facebook.hermes.intl.c
    public String e(AttributedCharacterIterator.Attribute attribute, double d3) {
        return attribute == NumberFormat.Field.SIGN ? Double.compare(d3, 0.0d) >= 0 ? "plusSign" : "minusSign" : attribute == NumberFormat.Field.INTEGER ? Double.isNaN(d3) ? "nan" : Double.isInfinite(d3) ? "infinity" : "integer" : attribute == NumberFormat.Field.FRACTION ? "fraction" : attribute == NumberFormat.Field.EXPONENT ? "exponentInteger" : attribute == NumberFormat.Field.EXPONENT_SIGN ? "exponentMinusSign" : attribute == NumberFormat.Field.EXPONENT_SYMBOL ? "exponentSeparator" : attribute == NumberFormat.Field.DECIMAL_SEPARATOR ? "decimal" : attribute == NumberFormat.Field.GROUPING_SEPARATOR ? "group" : attribute == NumberFormat.Field.PERCENT ? "percentSign" : attribute == NumberFormat.Field.PERMILLE ? "permilleSign" : attribute == NumberFormat.Field.CURRENCY ? "currency" : attribute.toString().equals("android.icu.text.NumberFormat$Field(compact)") ? "compact" : "literal";
    }

    @Override // com.facebook.hermes.intl.c
    /* JADX INFO: renamed from: m, reason: merged with bridge method [inline-methods] */
    public j i(A0.b bVar, String str, c.h hVar, c.d dVar, c.e eVar, c.b bVar2) throws A0.e {
        if (!str.isEmpty()) {
            try {
                if (NumberingSystem.getInstanceByName(A0.d.h(str)) == null) {
                    throw new A0.e("Invalid numbering system: " + str);
                }
                ArrayList arrayList = new ArrayList();
                arrayList.add(A0.d.h(str));
                bVar.g("nu", arrayList);
            } catch (RuntimeException unused) {
                throw new A0.e("Invalid numbering system: " + str);
            }
        }
        if (eVar == c.e.COMPACT && (hVar == c.h.DECIMAL || hVar == c.h.UNIT)) {
            o(CompactDecimalFormat.getInstance((ULocale) bVar.h(), bVar2 == c.b.SHORT ? CompactDecimalFormat.CompactStyle.SHORT : CompactDecimalFormat.CompactStyle.LONG), bVar, hVar);
        } else {
            android.icu.text.NumberFormat numberFormat = android.icu.text.NumberFormat.getInstance((ULocale) bVar.h(), hVar.b(eVar, dVar));
            if (eVar == c.e.ENGINEERING) {
                numberFormat.setMaximumIntegerDigits(3);
            }
            o(numberFormat, bVar, hVar);
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.c
    /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
    public j j(String str, c.EnumC0094c enumC0094c) {
        if (this.f6039d == c.h.CURRENCY) {
            Currency currency = Currency.getInstance(str);
            this.f6037b.setCurrency(currency);
            if (enumC0094c != c.EnumC0094c.CODE) {
                str = currency.getName(this.f6038c.h(), enumC0094c.b(), (boolean[]) null);
            }
            android.icu.text.NumberFormat numberFormat = this.f6037b;
            if (numberFormat instanceof DecimalFormat) {
                DecimalFormat decimalFormat = (DecimalFormat) numberFormat;
                DecimalFormatSymbols decimalFormatSymbols = decimalFormat.getDecimalFormatSymbols();
                decimalFormatSymbols.setCurrencySymbol(str);
                decimalFormat.setDecimalFormatSymbols(decimalFormatSymbols);
            }
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.c
    /* JADX INFO: renamed from: r, reason: merged with bridge method [inline-methods] */
    public j l(c.f fVar, int i3, int i4) {
        if (fVar == c.f.FRACTION_DIGITS) {
            if (i3 >= 0) {
                this.f6037b.setMinimumFractionDigits(i3);
            }
            if (i4 >= 0) {
                this.f6037b.setMaximumFractionDigits(i4);
            }
            android.icu.text.NumberFormat numberFormat = this.f6037b;
            if (numberFormat instanceof DecimalFormat) {
                ((DecimalFormat) numberFormat).setSignificantDigitsUsed(false);
            }
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.c
    /* JADX INFO: renamed from: s, reason: merged with bridge method [inline-methods] */
    public j k(boolean z3) {
        this.f6037b.setGroupingUsed(z3);
        return this;
    }

    @Override // com.facebook.hermes.intl.c
    /* JADX INFO: renamed from: t, reason: merged with bridge method [inline-methods] */
    public j h(int i3) {
        if (i3 != -1) {
            this.f6037b.setMinimumIntegerDigits(i3);
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.c
    /* JADX INFO: renamed from: u, reason: merged with bridge method [inline-methods] */
    public j g(c.g gVar) {
        android.icu.text.NumberFormat numberFormat = this.f6037b;
        if (numberFormat instanceof DecimalFormat) {
            DecimalFormat decimalFormat = (DecimalFormat) numberFormat;
            DecimalFormatSymbols decimalFormatSymbols = decimalFormat.getDecimalFormatSymbols();
            if (Build.VERSION.SDK_INT >= 31) {
                int i3 = a.f6041a[gVar.ordinal()];
                if (i3 == 1) {
                    decimalFormat.setSignAlwaysShown(false);
                } else if (i3 == 2 || i3 == 3) {
                    decimalFormat.setSignAlwaysShown(true);
                }
            } else {
                int i4 = a.f6041a[gVar.ordinal()];
                if (i4 == 1) {
                    decimalFormat.setPositivePrefix("");
                    decimalFormat.setPositiveSuffix("");
                    decimalFormat.setNegativePrefix("");
                    decimalFormat.setNegativeSuffix("");
                } else if (i4 == 2 || i4 == 3) {
                    if (!decimalFormat.getNegativePrefix().isEmpty()) {
                        decimalFormat.setPositivePrefix(new String(new char[]{decimalFormatSymbols.getPlusSign()}));
                    }
                    if (!decimalFormat.getNegativeSuffix().isEmpty()) {
                        decimalFormat.setPositiveSuffix(new String(new char[]{decimalFormatSymbols.getPlusSign()}));
                    }
                }
            }
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.c
    /* JADX INFO: renamed from: v, reason: merged with bridge method [inline-methods] */
    public j d(c.f fVar, int i3, int i4) throws A0.e {
        android.icu.text.NumberFormat numberFormat = this.f6037b;
        if ((numberFormat instanceof DecimalFormat) && fVar == c.f.SIGNIFICANT_DIGITS) {
            DecimalFormat decimalFormat = (DecimalFormat) numberFormat;
            if (i3 >= 0) {
                decimalFormat.setMinimumSignificantDigits(i3);
            }
            if (i4 >= 0) {
                if (i4 < decimalFormat.getMinimumSignificantDigits()) {
                    throw new A0.e("maximumSignificantDigits should be at least equal to minimumSignificantDigits");
                }
                decimalFormat.setMaximumSignificantDigits(i4);
            }
            decimalFormat.setSignificantDigitsUsed(true);
        }
        return this;
    }

    @Override // com.facebook.hermes.intl.c
    /* JADX INFO: renamed from: w, reason: merged with bridge method [inline-methods] */
    public j f(String str, c.i iVar) {
        if (this.f6039d == c.h.UNIT) {
            this.f6040e = p(str);
            this.f6036a = MeasureFormat.getInstance(this.f6038c.h(), iVar.b(), this.f6037b);
        }
        return this;
    }
}
