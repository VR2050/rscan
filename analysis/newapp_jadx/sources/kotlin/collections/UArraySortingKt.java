package kotlin.collections;

import kotlin.ExperimentalUnsignedTypes;
import kotlin.Metadata;
import kotlin.UByteArray;
import kotlin.UIntArray;
import kotlin.ULongArray;
import kotlin.UShort;
import kotlin.UShortArray;
import kotlin.UnsignedKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5310d1 = {"\u00000\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0010\u001a*\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0003ø\u0001\u0000¢\u0006\u0004\b\u0006\u0010\u0007\u001a*\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\b2\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0003ø\u0001\u0000¢\u0006\u0004\b\t\u0010\n\u001a*\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u000b2\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0003ø\u0001\u0000¢\u0006\u0004\b\f\u0010\r\u001a*\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u000e2\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0003ø\u0001\u0000¢\u0006\u0004\b\u000f\u0010\u0010\u001a*\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0003ø\u0001\u0000¢\u0006\u0004\b\u0013\u0010\u0014\u001a*\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0002\u001a\u00020\b2\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0003ø\u0001\u0000¢\u0006\u0004\b\u0015\u0010\u0016\u001a*\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0002\u001a\u00020\u000b2\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0003ø\u0001\u0000¢\u0006\u0004\b\u0017\u0010\u0018\u001a*\u0010\u0011\u001a\u00020\u00122\u0006\u0010\u0002\u001a\u00020\u000e2\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0003ø\u0001\u0000¢\u0006\u0004\b\u0019\u0010\u001a\u001a*\u0010\u001b\u001a\u00020\u00122\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u001c\u001a\u00020\u00012\u0006\u0010\u001d\u001a\u00020\u0001H\u0001ø\u0001\u0000¢\u0006\u0004\b\u001e\u0010\u0014\u001a*\u0010\u001b\u001a\u00020\u00122\u0006\u0010\u0002\u001a\u00020\b2\u0006\u0010\u001c\u001a\u00020\u00012\u0006\u0010\u001d\u001a\u00020\u0001H\u0001ø\u0001\u0000¢\u0006\u0004\b\u001f\u0010\u0016\u001a*\u0010\u001b\u001a\u00020\u00122\u0006\u0010\u0002\u001a\u00020\u000b2\u0006\u0010\u001c\u001a\u00020\u00012\u0006\u0010\u001d\u001a\u00020\u0001H\u0001ø\u0001\u0000¢\u0006\u0004\b \u0010\u0018\u001a*\u0010\u001b\u001a\u00020\u00122\u0006\u0010\u0002\u001a\u00020\u000e2\u0006\u0010\u001c\u001a\u00020\u00012\u0006\u0010\u001d\u001a\u00020\u0001H\u0001ø\u0001\u0000¢\u0006\u0004\b!\u0010\u001a\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\""}, m5311d2 = {"partition", "", "array", "Lkotlin/UByteArray;", "left", "right", "partition-4UcCI2c", "([BII)I", "Lkotlin/UIntArray;", "partition-oBK06Vg", "([III)I", "Lkotlin/ULongArray;", "partition--nroSd4", "([JII)I", "Lkotlin/UShortArray;", "partition-Aa5vz7o", "([SII)I", "quickSort", "", "quickSort-4UcCI2c", "([BII)V", "quickSort-oBK06Vg", "([III)V", "quickSort--nroSd4", "([JII)V", "quickSort-Aa5vz7o", "([SII)V", "sortArray", "fromIndex", "toIndex", "sortArray-4UcCI2c", "sortArray-oBK06Vg", "sortArray--nroSd4", "sortArray-Aa5vz7o", "kotlin-stdlib"}, m5312k = 2, m5313mv = {1, 6, 0}, m5315xi = 48)
/* loaded from: classes2.dex */
public final class UArraySortingKt {
    @ExperimentalUnsignedTypes
    /* renamed from: partition--nroSd4, reason: not valid java name */
    private static final int m6502partitionnroSd4(long[] jArr, int i2, int i3) {
        long m6286getsVKNKU = ULongArray.m6286getsVKNKU(jArr, (i2 + i3) / 2);
        while (i2 <= i3) {
            while (UnsignedKt.ulongCompare(ULongArray.m6286getsVKNKU(jArr, i2), m6286getsVKNKU) < 0) {
                i2++;
            }
            while (UnsignedKt.ulongCompare(ULongArray.m6286getsVKNKU(jArr, i3), m6286getsVKNKU) > 0) {
                i3--;
            }
            if (i2 <= i3) {
                long m6286getsVKNKU2 = ULongArray.m6286getsVKNKU(jArr, i2);
                ULongArray.m6291setk8EXiF4(jArr, i2, ULongArray.m6286getsVKNKU(jArr, i3));
                ULongArray.m6291setk8EXiF4(jArr, i3, m6286getsVKNKU2);
                i2++;
                i3--;
            }
        }
        return i2;
    }

    @ExperimentalUnsignedTypes
    /* renamed from: partition-4UcCI2c, reason: not valid java name */
    private static final int m6503partition4UcCI2c(byte[] bArr, int i2, int i3) {
        int i4;
        byte m6130getw2LRezQ = UByteArray.m6130getw2LRezQ(bArr, (i2 + i3) / 2);
        while (i2 <= i3) {
            while (true) {
                i4 = m6130getw2LRezQ & 255;
                if (Intrinsics.compare(UByteArray.m6130getw2LRezQ(bArr, i2) & 255, i4) >= 0) {
                    break;
                }
                i2++;
            }
            while (Intrinsics.compare(UByteArray.m6130getw2LRezQ(bArr, i3) & 255, i4) > 0) {
                i3--;
            }
            if (i2 <= i3) {
                byte m6130getw2LRezQ2 = UByteArray.m6130getw2LRezQ(bArr, i2);
                UByteArray.m6135setVurrAj0(bArr, i2, UByteArray.m6130getw2LRezQ(bArr, i3));
                UByteArray.m6135setVurrAj0(bArr, i3, m6130getw2LRezQ2);
                i2++;
                i3--;
            }
        }
        return i2;
    }

    @ExperimentalUnsignedTypes
    /* renamed from: partition-Aa5vz7o, reason: not valid java name */
    private static final int m6504partitionAa5vz7o(short[] sArr, int i2, int i3) {
        int i4;
        short m6390getMh2AYeg = UShortArray.m6390getMh2AYeg(sArr, (i2 + i3) / 2);
        while (i2 <= i3) {
            while (true) {
                int m6390getMh2AYeg2 = UShortArray.m6390getMh2AYeg(sArr, i2) & UShort.MAX_VALUE;
                i4 = m6390getMh2AYeg & UShort.MAX_VALUE;
                if (Intrinsics.compare(m6390getMh2AYeg2, i4) >= 0) {
                    break;
                }
                i2++;
            }
            while (Intrinsics.compare(UShortArray.m6390getMh2AYeg(sArr, i3) & UShort.MAX_VALUE, i4) > 0) {
                i3--;
            }
            if (i2 <= i3) {
                short m6390getMh2AYeg3 = UShortArray.m6390getMh2AYeg(sArr, i2);
                UShortArray.m6395set01HTLdE(sArr, i2, UShortArray.m6390getMh2AYeg(sArr, i3));
                UShortArray.m6395set01HTLdE(sArr, i3, m6390getMh2AYeg3);
                i2++;
                i3--;
            }
        }
        return i2;
    }

    @ExperimentalUnsignedTypes
    /* renamed from: partition-oBK06Vg, reason: not valid java name */
    private static final int m6505partitionoBK06Vg(int[] iArr, int i2, int i3) {
        int m6208getpVg5ArA = UIntArray.m6208getpVg5ArA(iArr, (i2 + i3) / 2);
        while (i2 <= i3) {
            while (UnsignedKt.uintCompare(UIntArray.m6208getpVg5ArA(iArr, i2), m6208getpVg5ArA) < 0) {
                i2++;
            }
            while (UnsignedKt.uintCompare(UIntArray.m6208getpVg5ArA(iArr, i3), m6208getpVg5ArA) > 0) {
                i3--;
            }
            if (i2 <= i3) {
                int m6208getpVg5ArA2 = UIntArray.m6208getpVg5ArA(iArr, i2);
                UIntArray.m6213setVXSXFK8(iArr, i2, UIntArray.m6208getpVg5ArA(iArr, i3));
                UIntArray.m6213setVXSXFK8(iArr, i3, m6208getpVg5ArA2);
                i2++;
                i3--;
            }
        }
        return i2;
    }

    @ExperimentalUnsignedTypes
    /* renamed from: quickSort--nroSd4, reason: not valid java name */
    private static final void m6506quickSortnroSd4(long[] jArr, int i2, int i3) {
        int m6502partitionnroSd4 = m6502partitionnroSd4(jArr, i2, i3);
        int i4 = m6502partitionnroSd4 - 1;
        if (i2 < i4) {
            m6506quickSortnroSd4(jArr, i2, i4);
        }
        if (m6502partitionnroSd4 < i3) {
            m6506quickSortnroSd4(jArr, m6502partitionnroSd4, i3);
        }
    }

    @ExperimentalUnsignedTypes
    /* renamed from: quickSort-4UcCI2c, reason: not valid java name */
    private static final void m6507quickSort4UcCI2c(byte[] bArr, int i2, int i3) {
        int m6503partition4UcCI2c = m6503partition4UcCI2c(bArr, i2, i3);
        int i4 = m6503partition4UcCI2c - 1;
        if (i2 < i4) {
            m6507quickSort4UcCI2c(bArr, i2, i4);
        }
        if (m6503partition4UcCI2c < i3) {
            m6507quickSort4UcCI2c(bArr, m6503partition4UcCI2c, i3);
        }
    }

    @ExperimentalUnsignedTypes
    /* renamed from: quickSort-Aa5vz7o, reason: not valid java name */
    private static final void m6508quickSortAa5vz7o(short[] sArr, int i2, int i3) {
        int m6504partitionAa5vz7o = m6504partitionAa5vz7o(sArr, i2, i3);
        int i4 = m6504partitionAa5vz7o - 1;
        if (i2 < i4) {
            m6508quickSortAa5vz7o(sArr, i2, i4);
        }
        if (m6504partitionAa5vz7o < i3) {
            m6508quickSortAa5vz7o(sArr, m6504partitionAa5vz7o, i3);
        }
    }

    @ExperimentalUnsignedTypes
    /* renamed from: quickSort-oBK06Vg, reason: not valid java name */
    private static final void m6509quickSortoBK06Vg(int[] iArr, int i2, int i3) {
        int m6505partitionoBK06Vg = m6505partitionoBK06Vg(iArr, i2, i3);
        int i4 = m6505partitionoBK06Vg - 1;
        if (i2 < i4) {
            m6509quickSortoBK06Vg(iArr, i2, i4);
        }
        if (m6505partitionoBK06Vg < i3) {
            m6509quickSortoBK06Vg(iArr, m6505partitionoBK06Vg, i3);
        }
    }

    @ExperimentalUnsignedTypes
    /* renamed from: sortArray--nroSd4, reason: not valid java name */
    public static final void m6510sortArraynroSd4(@NotNull long[] array, int i2, int i3) {
        Intrinsics.checkNotNullParameter(array, "array");
        m6506quickSortnroSd4(array, i2, i3 - 1);
    }

    @ExperimentalUnsignedTypes
    /* renamed from: sortArray-4UcCI2c, reason: not valid java name */
    public static final void m6511sortArray4UcCI2c(@NotNull byte[] array, int i2, int i3) {
        Intrinsics.checkNotNullParameter(array, "array");
        m6507quickSort4UcCI2c(array, i2, i3 - 1);
    }

    @ExperimentalUnsignedTypes
    /* renamed from: sortArray-Aa5vz7o, reason: not valid java name */
    public static final void m6512sortArrayAa5vz7o(@NotNull short[] array, int i2, int i3) {
        Intrinsics.checkNotNullParameter(array, "array");
        m6508quickSortAa5vz7o(array, i2, i3 - 1);
    }

    @ExperimentalUnsignedTypes
    /* renamed from: sortArray-oBK06Vg, reason: not valid java name */
    public static final void m6513sortArrayoBK06Vg(@NotNull int[] array, int i2, int i3) {
        Intrinsics.checkNotNullParameter(array, "array");
        m6509quickSortoBK06Vg(array, i2, i3 - 1);
    }
}
