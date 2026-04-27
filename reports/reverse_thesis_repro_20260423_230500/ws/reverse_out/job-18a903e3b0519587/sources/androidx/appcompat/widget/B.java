package androidx.appcompat.widget;

import android.view.textclassifier.TextClassificationManager;
import android.view.textclassifier.TextClassifier;
import android.widget.TextView;

/* JADX INFO: loaded from: classes.dex */
final class B {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private TextView f3702a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private TextClassifier f3703b;

    private static final class a {
        static TextClassifier a(TextView textView) {
            TextClassificationManager textClassificationManager = (TextClassificationManager) textView.getContext().getSystemService(TextClassificationManager.class);
            return textClassificationManager != null ? textClassificationManager.getTextClassifier() : TextClassifier.NO_OP;
        }
    }

    B(TextView textView) {
        this.f3702a = (TextView) q.g.f(textView);
    }

    public TextClassifier a() {
        TextClassifier textClassifier = this.f3703b;
        return textClassifier == null ? a.a(this.f3702a) : textClassifier;
    }

    public void b(TextClassifier textClassifier) {
        this.f3703b = textClassifier;
    }
}
