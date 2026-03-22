package androidx.constraintlayout.solver.state.helpers;

import androidx.constraintlayout.solver.state.HelperReference;
import androidx.constraintlayout.solver.state.State;
import androidx.constraintlayout.solver.widgets.Barrier;
import androidx.constraintlayout.solver.widgets.HelperWidget;

/* loaded from: classes.dex */
public class BarrierReference extends HelperReference {
    private Barrier mBarrierWidget;
    private State.Direction mDirection;
    private int mMargin;

    /* renamed from: androidx.constraintlayout.solver.state.helpers.BarrierReference$1 */
    public static /* synthetic */ class C02421 {

        /* renamed from: $SwitchMap$androidx$constraintlayout$solver$state$State$Direction */
        public static final /* synthetic */ int[] f138xf452c4aa;

        static {
            State.Direction.values();
            int[] iArr = new int[6];
            f138xf452c4aa = iArr;
            try {
                iArr[State.Direction.LEFT.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f138xf452c4aa[State.Direction.START.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f138xf452c4aa[State.Direction.RIGHT.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f138xf452c4aa[State.Direction.END.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                f138xf452c4aa[State.Direction.TOP.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                f138xf452c4aa[State.Direction.BOTTOM.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
        }
    }

    public BarrierReference(State state) {
        super(state, State.Helper.BARRIER);
    }

    /* JADX WARN: Code restructure failed: missing block: B:9:0x0019, code lost:
    
        if (r0 != 5) goto L11;
     */
    @Override // androidx.constraintlayout.solver.state.HelperReference
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void apply() {
        /*
            r5 = this;
            r5.getHelperWidget()
            androidx.constraintlayout.solver.state.State$Direction r0 = r5.mDirection
            int r0 = r0.ordinal()
            r1 = 3
            r2 = 2
            r3 = 1
            r4 = 0
            if (r0 == 0) goto L1b
            if (r0 == r3) goto L1f
            if (r0 == r2) goto L1b
            if (r0 == r1) goto L1f
            r3 = 4
            if (r0 == r3) goto L1d
            r2 = 5
            if (r0 == r2) goto L20
        L1b:
            r1 = 0
            goto L20
        L1d:
            r1 = 2
            goto L20
        L1f:
            r1 = 1
        L20:
            androidx.constraintlayout.solver.widgets.Barrier r0 = r5.mBarrierWidget
            r0.setBarrierType(r1)
            androidx.constraintlayout.solver.widgets.Barrier r0 = r5.mBarrierWidget
            int r1 = r5.mMargin
            r0.setMargin(r1)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.solver.state.helpers.BarrierReference.apply():void");
    }

    @Override // androidx.constraintlayout.solver.state.HelperReference
    public HelperWidget getHelperWidget() {
        if (this.mBarrierWidget == null) {
            this.mBarrierWidget = new Barrier();
        }
        return this.mBarrierWidget;
    }

    public void margin(Object obj) {
        margin(this.mState.convertDimension(obj));
    }

    public void setBarrierDirection(State.Direction direction) {
        this.mDirection = direction;
    }

    public void margin(int i2) {
        this.mMargin = i2;
    }
}
