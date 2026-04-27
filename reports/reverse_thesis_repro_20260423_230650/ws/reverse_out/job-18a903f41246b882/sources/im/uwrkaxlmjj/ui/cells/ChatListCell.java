package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.RectF;
import android.text.TextPaint;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadioButton;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChatListCell extends LinearLayout {
    private ListView[] listView;

    private class ListView extends FrameLayout {
        private RadioButton button;
        private boolean isThreeLines;
        private RectF rect;
        private TextPaint textPaint;

        public ListView(Context context, boolean threeLines) {
            super(context);
            this.rect = new RectF();
            boolean z = true;
            this.textPaint = new TextPaint(1);
            setWillNotDraw(false);
            this.isThreeLines = threeLines;
            this.textPaint.setTextSize(AndroidUtilities.dp(13.0f));
            RadioButton radioButton = new RadioButton(context) { // from class: im.uwrkaxlmjj.ui.cells.ChatListCell.ListView.1
                @Override // android.view.View
                public void invalidate() {
                    super.invalidate();
                    ListView.this.invalidate();
                }
            };
            this.button = radioButton;
            radioButton.setSize(AndroidUtilities.dp(20.0f));
            addView(this.button, LayoutHelper.createFrame(22.0f, 22.0f, 53, 0.0f, 26.0f, 10.0f, 0.0f));
            RadioButton radioButton2 = this.button;
            if ((!this.isThreeLines || !SharedConfig.useThreeLinesLayout) && (this.isThreeLines || SharedConfig.useThreeLinesLayout)) {
                z = false;
            }
            radioButton2.setChecked(z, false);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            int i;
            String str;
            int color = Theme.getColor(Theme.key_switchTrack);
            int r = Color.red(color);
            int g = Color.green(color);
            int b = Color.blue(color);
            this.button.setColor(Theme.getColor(Theme.key_radioBackground), Theme.getColor(Theme.key_radioBackgroundChecked));
            this.rect.set(AndroidUtilities.dp(1.0f), AndroidUtilities.dp(1.0f), getMeasuredWidth() - AndroidUtilities.dp(1.0f), AndroidUtilities.dp(73.0f));
            Theme.chat_instantViewRectPaint.setColor(Color.argb((int) (this.button.getProgress() * 43.0f), r, g, b));
            canvas.drawRoundRect(this.rect, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), Theme.chat_instantViewRectPaint);
            this.rect.set(0.0f, 0.0f, getMeasuredWidth(), AndroidUtilities.dp(74.0f));
            Theme.dialogs_onlineCirclePaint.setColor(Color.argb((int) ((1.0f - this.button.getProgress()) * 31.0f), r, g, b));
            canvas.drawRoundRect(this.rect, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), Theme.dialogs_onlineCirclePaint);
            if (this.isThreeLines) {
                i = R.string.ChatListExpanded;
                str = "ChatListExpanded";
            } else {
                i = R.string.ChatListDefault;
                str = "ChatListDefault";
            }
            String text = LocaleController.getString(str, i);
            int width = (int) Math.ceil(this.textPaint.measureText(text));
            this.textPaint.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            canvas.drawText(text, (getMeasuredWidth() - width) / 2, AndroidUtilities.dp(96.0f), this.textPaint);
            int a = 0;
            for (int i2 = 2; a < i2; i2 = 2) {
                int cy = AndroidUtilities.dp(a == 0 ? 21.0f : 53.0f);
                Theme.dialogs_onlineCirclePaint.setColor(Color.argb(a == 0 ? 204 : 90, r, g, b));
                canvas.drawCircle(AndroidUtilities.dp(22.0f), cy, AndroidUtilities.dp(11.0f), Theme.dialogs_onlineCirclePaint);
                int i3 = 0;
                while (true) {
                    if (i3 < (this.isThreeLines ? 3 : 2)) {
                        Theme.dialogs_onlineCirclePaint.setColor(Color.argb(i3 == 0 ? 204 : 90, r, g, b));
                        if (this.isThreeLines) {
                            this.rect.set(AndroidUtilities.dp(41.0f), cy - AndroidUtilities.dp(8.3f - (i3 * 7)), getMeasuredWidth() - AndroidUtilities.dp(i3 != 0 ? 48.0f : 72.0f), cy - AndroidUtilities.dp(5.3f - (i3 * 7)));
                            canvas.drawRoundRect(this.rect, AndroidUtilities.dpf2(1.5f), AndroidUtilities.dpf2(1.5f), Theme.dialogs_onlineCirclePaint);
                        } else {
                            this.rect.set(AndroidUtilities.dp(41.0f), cy - AndroidUtilities.dp(7 - (i3 * 10)), getMeasuredWidth() - AndroidUtilities.dp(i3 != 0 ? 48.0f : 72.0f), cy - AndroidUtilities.dp(3 - (i3 * 10)));
                            canvas.drawRoundRect(this.rect, AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), Theme.dialogs_onlineCirclePaint);
                        }
                        i3++;
                    }
                }
                a++;
            }
        }
    }

    public ChatListCell(Context context) {
        super(context);
        this.listView = new ListView[2];
        setOrientation(0);
        setPadding(AndroidUtilities.dp(21.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(21.0f), 0);
        int a = 0;
        while (a < this.listView.length) {
            final boolean isThreeLines = a == 1;
            this.listView[a] = new ListView(context, isThreeLines);
            addView(this.listView[a], LayoutHelper.createLinear(-1, -1, 0.5f, a == 1 ? 10 : 0, 0, 0, 0));
            this.listView[a].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.cells.-$$Lambda$ChatListCell$UxwrOX1zTJYw5b5sBoIqcFNW5oo
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$0$ChatListCell(isThreeLines, view);
                }
            });
            a++;
        }
    }

    public /* synthetic */ void lambda$new$0$ChatListCell(boolean isThreeLines, View v) {
        for (int b = 0; b < 2; b++) {
            this.listView[b].button.setChecked(this.listView[b] == v, true);
        }
        didSelectChatType(isThreeLines);
    }

    protected void didSelectChatType(boolean threeLines) {
    }

    @Override // android.view.View
    public void invalidate() {
        super.invalidate();
        int a = 0;
        while (true) {
            ListView[] listViewArr = this.listView;
            if (a < listViewArr.length) {
                listViewArr[a].invalidate();
                a++;
            } else {
                return;
            }
        }
    }

    @Override // android.widget.LinearLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(123.0f), 1073741824));
    }
}
