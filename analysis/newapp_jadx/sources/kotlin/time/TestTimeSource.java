package kotlin.time;

import kotlin.Metadata;
import kotlin.SinceKotlin;
import p005b.p131d.p132a.p133a.C1499a;

@SinceKotlin(version = "1.3")
@Metadata(m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\t\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\b\u0007\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u001a\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\bH\u0002ø\u0001\u0000¢\u0006\u0004\b\t\u0010\nJ\u001b\u0010\u000b\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\bH\u0086\u0002ø\u0001\u0000¢\u0006\u0004\b\f\u0010\nJ\b\u0010\r\u001a\u00020\u0004H\u0014R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082\u000e¢\u0006\u0002\n\u0000\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006\u000e"}, m5311d2 = {"Lkotlin/time/TestTimeSource;", "Lkotlin/time/AbstractLongTimeSource;", "()V", "reading", "", "overflow", "", "duration", "Lkotlin/time/Duration;", "overflow-LRDsOJo", "(J)V", "plusAssign", "plusAssign-LRDsOJo", "read", "kotlin-stdlib"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
@ExperimentalTime
/* loaded from: classes2.dex */
public final class TestTimeSource extends AbstractLongTimeSource {
    private long reading;

    public TestTimeSource() {
        super(DurationUnit.NANOSECONDS);
    }

    /* renamed from: overflow-LRDsOJo, reason: not valid java name */
    private final void m7481overflowLRDsOJo(long duration) {
        StringBuilder m586H = C1499a.m586H("TestTimeSource will overflow if its reading ");
        m586H.append(this.reading);
        m586H.append("ns is advanced by ");
        m586H.append((Object) Duration.m7403toStringimpl(duration));
        m586H.append('.');
        throw new IllegalStateException(m586H.toString());
    }

    /* renamed from: plusAssign-LRDsOJo, reason: not valid java name */
    public final void m7482plusAssignLRDsOJo(long duration) {
        long j2;
        long m7400toLongimpl = Duration.m7400toLongimpl(duration, getUnit());
        if (m7400toLongimpl == Long.MIN_VALUE || m7400toLongimpl == Long.MAX_VALUE) {
            double m7397toDoubleimpl = this.reading + Duration.m7397toDoubleimpl(duration, getUnit());
            if (m7397toDoubleimpl > 9.223372036854776E18d || m7397toDoubleimpl < -9.223372036854776E18d) {
                m7481overflowLRDsOJo(duration);
            }
            j2 = (long) m7397toDoubleimpl;
        } else {
            long j3 = this.reading;
            j2 = j3 + m7400toLongimpl;
            if ((m7400toLongimpl ^ j3) >= 0 && (j3 ^ j2) < 0) {
                m7481overflowLRDsOJo(duration);
            }
        }
        this.reading = j2;
    }

    @Override // kotlin.time.AbstractLongTimeSource
    /* renamed from: read, reason: from getter */
    public long getReading() {
        return this.reading;
    }
}
