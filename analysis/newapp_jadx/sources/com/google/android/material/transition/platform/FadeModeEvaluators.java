package com.google.android.material.transition.platform;

import androidx.annotation.RequiresApi;
import p005b.p131d.p132a.p133a.C1499a;

@RequiresApi(21)
/* loaded from: classes2.dex */
public class FadeModeEvaluators {

    /* renamed from: IN */
    private static final FadeModeEvaluator f9869IN = new FadeModeEvaluator() { // from class: com.google.android.material.transition.platform.FadeModeEvaluators.1
        @Override // com.google.android.material.transition.platform.FadeModeEvaluator
        public FadeModeResult evaluate(float f2, float f3, float f4) {
            return FadeModeResult.endOnTop(255, TransitionUtils.lerp(0, 255, f3, f4, f2));
        }
    };
    private static final FadeModeEvaluator OUT = new FadeModeEvaluator() { // from class: com.google.android.material.transition.platform.FadeModeEvaluators.2
        @Override // com.google.android.material.transition.platform.FadeModeEvaluator
        public FadeModeResult evaluate(float f2, float f3, float f4) {
            return FadeModeResult.startOnTop(TransitionUtils.lerp(255, 0, f3, f4, f2), 255);
        }
    };
    private static final FadeModeEvaluator CROSS = new FadeModeEvaluator() { // from class: com.google.android.material.transition.platform.FadeModeEvaluators.3
        @Override // com.google.android.material.transition.platform.FadeModeEvaluator
        public FadeModeResult evaluate(float f2, float f3, float f4) {
            return FadeModeResult.startOnTop(TransitionUtils.lerp(255, 0, f3, f4, f2), TransitionUtils.lerp(0, 255, f3, f4, f2));
        }
    };
    private static final FadeModeEvaluator THROUGH = new FadeModeEvaluator() { // from class: com.google.android.material.transition.platform.FadeModeEvaluators.4
        @Override // com.google.android.material.transition.platform.FadeModeEvaluator
        public FadeModeResult evaluate(float f2, float f3, float f4) {
            float m627m = C1499a.m627m(f4, f3, 0.35f, f3);
            return FadeModeResult.startOnTop(TransitionUtils.lerp(255, 0, f3, m627m, f2), TransitionUtils.lerp(0, 255, m627m, f4, f2));
        }
    };

    private FadeModeEvaluators() {
    }

    public static FadeModeEvaluator get(int i2, boolean z) {
        if (i2 == 0) {
            return z ? f9869IN : OUT;
        }
        if (i2 == 1) {
            return z ? OUT : f9869IN;
        }
        if (i2 == 2) {
            return CROSS;
        }
        if (i2 == 3) {
            return THROUGH;
        }
        throw new IllegalArgumentException(C1499a.m626l("Invalid fade mode: ", i2));
    }
}
