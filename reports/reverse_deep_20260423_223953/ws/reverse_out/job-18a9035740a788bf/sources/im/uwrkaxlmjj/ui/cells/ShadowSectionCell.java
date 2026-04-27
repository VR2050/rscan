package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.view.View;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class ShadowSectionCell extends View {
    private int size;

    public ShadowSectionCell(Context context) {
        this(context, 10);
    }

    public ShadowSectionCell(Context context, int s) {
        super(context);
        setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.size = s;
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(this.size), 1073741824));
    }
}
