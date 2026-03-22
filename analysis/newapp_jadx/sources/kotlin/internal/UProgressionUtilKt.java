package kotlin.internal;

import kotlin.Metadata;
import kotlin.PublishedApi;
import kotlin.SinceKotlin;
import kotlin.UInt;
import kotlin.ULong;
import kotlin.UnsignedKt;

@Metadata(m5310d1 = {"\u0000 \n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\b\n\u0000\n\u0002\u0010\t\n\u0002\b\u0002\u001a*\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u00012\u0006\u0010\u0004\u001a\u00020\u0001H\u0002ø\u0001\u0000¢\u0006\u0004\b\u0005\u0010\u0006\u001a*\u0010\u0000\u001a\u00020\u00072\u0006\u0010\u0002\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u00072\u0006\u0010\u0004\u001a\u00020\u0007H\u0002ø\u0001\u0000¢\u0006\u0004\b\b\u0010\t\u001a*\u0010\n\u001a\u00020\u00012\u0006\u0010\u000b\u001a\u00020\u00012\u0006\u0010\f\u001a\u00020\u00012\u0006\u0010\r\u001a\u00020\u000eH\u0001ø\u0001\u0000¢\u0006\u0004\b\u000f\u0010\u0006\u001a*\u0010\n\u001a\u00020\u00072\u0006\u0010\u000b\u001a\u00020\u00072\u0006\u0010\f\u001a\u00020\u00072\u0006\u0010\r\u001a\u00020\u0010H\u0001ø\u0001\u0000¢\u0006\u0004\b\u0011\u0010\t\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u0012"}, m5311d2 = {"differenceModulo", "Lkotlin/UInt;", "a", "b", "c", "differenceModulo-WZ9TVnA", "(III)I", "Lkotlin/ULong;", "differenceModulo-sambcqE", "(JJJ)J", "getProgressionLastElement", "start", "end", "step", "", "getProgressionLastElement-Nkh28Cs", "", "getProgressionLastElement-7ftBX0g", "kotlin-stdlib"}, m5312k = 2, m5313mv = {1, 6, 0}, m5315xi = 48)
/* loaded from: classes2.dex */
public final class UProgressionUtilKt {
    /* renamed from: differenceModulo-WZ9TVnA, reason: not valid java name */
    private static final int m7243differenceModuloWZ9TVnA(int i2, int i3, int i4) {
        int m6403uintRemainderJ1ME1BU = UnsignedKt.m6403uintRemainderJ1ME1BU(i2, i4);
        int m6403uintRemainderJ1ME1BU2 = UnsignedKt.m6403uintRemainderJ1ME1BU(i3, i4);
        int uintCompare = UnsignedKt.uintCompare(m6403uintRemainderJ1ME1BU, m6403uintRemainderJ1ME1BU2);
        int m6149constructorimpl = UInt.m6149constructorimpl(m6403uintRemainderJ1ME1BU - m6403uintRemainderJ1ME1BU2);
        return uintCompare >= 0 ? m6149constructorimpl : UInt.m6149constructorimpl(m6149constructorimpl + i4);
    }

    /* renamed from: differenceModulo-sambcqE, reason: not valid java name */
    private static final long m7244differenceModulosambcqE(long j2, long j3, long j4) {
        long m6405ulongRemaindereb3DHEI = UnsignedKt.m6405ulongRemaindereb3DHEI(j2, j4);
        long m6405ulongRemaindereb3DHEI2 = UnsignedKt.m6405ulongRemaindereb3DHEI(j3, j4);
        int ulongCompare = UnsignedKt.ulongCompare(m6405ulongRemaindereb3DHEI, m6405ulongRemaindereb3DHEI2);
        long m6227constructorimpl = ULong.m6227constructorimpl(m6405ulongRemaindereb3DHEI - m6405ulongRemaindereb3DHEI2);
        return ulongCompare >= 0 ? m6227constructorimpl : ULong.m6227constructorimpl(m6227constructorimpl + j4);
    }

    @SinceKotlin(version = "1.3")
    @PublishedApi
    /* renamed from: getProgressionLastElement-7ftBX0g, reason: not valid java name */
    public static final long m7245getProgressionLastElement7ftBX0g(long j2, long j3, long j4) {
        if (j4 > 0) {
            return UnsignedKt.ulongCompare(j2, j3) >= 0 ? j3 : ULong.m6227constructorimpl(j3 - m7244differenceModulosambcqE(j3, j2, ULong.m6227constructorimpl(j4)));
        }
        if (j4 < 0) {
            return UnsignedKt.ulongCompare(j2, j3) <= 0 ? j3 : ULong.m6227constructorimpl(j3 + m7244differenceModulosambcqE(j2, j3, ULong.m6227constructorimpl(-j4)));
        }
        throw new IllegalArgumentException("Step is zero.");
    }

    @SinceKotlin(version = "1.3")
    @PublishedApi
    /* renamed from: getProgressionLastElement-Nkh28Cs, reason: not valid java name */
    public static final int m7246getProgressionLastElementNkh28Cs(int i2, int i3, int i4) {
        if (i4 > 0) {
            return UnsignedKt.uintCompare(i2, i3) >= 0 ? i3 : UInt.m6149constructorimpl(i3 - m7243differenceModuloWZ9TVnA(i3, i2, UInt.m6149constructorimpl(i4)));
        }
        if (i4 < 0) {
            return UnsignedKt.uintCompare(i2, i3) <= 0 ? i3 : UInt.m6149constructorimpl(i3 + m7243differenceModuloWZ9TVnA(i2, i3, UInt.m6149constructorimpl(-i4)));
        }
        throw new IllegalArgumentException("Step is zero.");
    }
}
