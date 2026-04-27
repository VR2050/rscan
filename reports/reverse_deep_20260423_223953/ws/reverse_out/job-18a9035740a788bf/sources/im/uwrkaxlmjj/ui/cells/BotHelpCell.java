package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.Canvas;
import android.text.Layout;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.StaticLayout;
import android.text.style.ClickableSpan;
import android.text.style.URLSpan;
import android.view.MotionEvent;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LinkPath;
import im.uwrkaxlmjj.ui.components.TypefaceSpan;
import im.uwrkaxlmjj.ui.components.URLSpanNoUnderline;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class BotHelpCell extends View {
    private BotHelpCellDelegate delegate;
    private int height;
    private String oldText;
    private ClickableSpan pressedLink;
    private StaticLayout textLayout;
    private int textX;
    private int textY;
    private LinkPath urlPath;
    private int width;

    public interface BotHelpCellDelegate {
        void didPressUrl(String str);
    }

    public BotHelpCell(Context context) {
        super(context);
        this.urlPath = new LinkPath();
    }

    public void setDelegate(BotHelpCellDelegate botHelpCellDelegate) {
        this.delegate = botHelpCellDelegate;
    }

    private void resetPressedLink() {
        if (this.pressedLink != null) {
            this.pressedLink = null;
        }
        invalidate();
    }

    public void setText(String text) {
        int maxWidth;
        if (text == null || text.length() == 0) {
            setVisibility(8);
            return;
        }
        if (text != null && text.equals(this.oldText)) {
            return;
        }
        this.oldText = text;
        setVisibility(0);
        if (AndroidUtilities.isTablet()) {
            maxWidth = (int) (AndroidUtilities.getMinTabletSide() * 0.7f);
        } else {
            maxWidth = (int) (Math.min(AndroidUtilities.displaySize.x, AndroidUtilities.displaySize.y) * 0.7f);
        }
        String[] lines = text.split(ShellAdbUtils.COMMAND_LINE_END);
        SpannableStringBuilder stringBuilder = new SpannableStringBuilder();
        String help = LocaleController.getString("BotInfoTitle", R.string.BotInfoTitle);
        stringBuilder.append((CharSequence) help);
        stringBuilder.append("\n\n");
        for (int a = 0; a < lines.length; a++) {
            stringBuilder.append(lines[a].trim());
            if (a != lines.length - 1) {
                stringBuilder.append(ShellAdbUtils.COMMAND_LINE_END);
            }
        }
        MessageObject.addLinks(false, stringBuilder);
        stringBuilder.setSpan(new TypefaceSpan(AndroidUtilities.getTypeface("fonts/rmedium.ttf")), 0, help.length(), 33);
        Emoji.replaceEmoji(stringBuilder, Theme.chat_msgTextPaint.getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
        try {
            StaticLayout staticLayout = new StaticLayout(stringBuilder, Theme.chat_msgTextPaint, maxWidth, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
            this.textLayout = staticLayout;
            this.width = 0;
            this.height = staticLayout.getHeight() + AndroidUtilities.dp(22.0f);
            int count = this.textLayout.getLineCount();
            for (int a2 = 0; a2 < count; a2++) {
                this.width = (int) Math.ceil(Math.max(this.width, this.textLayout.getLineWidth(a2) + this.textLayout.getLineLeft(a2)));
            }
            int a3 = this.width;
            if (a3 > maxWidth) {
                this.width = maxWidth;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        this.width += AndroidUtilities.dp(22.0f);
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        float x = event.getX();
        float y = event.getY();
        boolean result = false;
        if (this.textLayout != null) {
            if (event.getAction() == 0 || (this.pressedLink != null && event.getAction() == 1)) {
                if (event.getAction() == 0) {
                    resetPressedLink();
                    try {
                        int x2 = (int) (x - this.textX);
                        int y2 = (int) (y - this.textY);
                        int line = this.textLayout.getLineForVertical(y2);
                        int off = this.textLayout.getOffsetForHorizontal(line, x2);
                        float left = this.textLayout.getLineLeft(line);
                        if (left <= x2 && this.textLayout.getLineWidth(line) + left >= x2) {
                            Spannable buffer = (Spannable) this.textLayout.getText();
                            ClickableSpan[] link = (ClickableSpan[]) buffer.getSpans(off, off, ClickableSpan.class);
                            if (link.length != 0) {
                                resetPressedLink();
                                ClickableSpan clickableSpan = link[0];
                                this.pressedLink = clickableSpan;
                                result = true;
                                try {
                                    int start = buffer.getSpanStart(clickableSpan);
                                    this.urlPath.setCurrentLayout(this.textLayout, start, 0.0f);
                                    this.textLayout.getSelectionPath(start, buffer.getSpanEnd(this.pressedLink), this.urlPath);
                                } catch (Exception e) {
                                    FileLog.e(e);
                                }
                            } else {
                                resetPressedLink();
                            }
                        } else {
                            resetPressedLink();
                        }
                    } catch (Exception e2) {
                        resetPressedLink();
                        FileLog.e(e2);
                    }
                } else {
                    ClickableSpan clickableSpan2 = this.pressedLink;
                    if (clickableSpan2 != null) {
                        try {
                            if (clickableSpan2 instanceof URLSpanNoUnderline) {
                                String url = ((URLSpanNoUnderline) clickableSpan2).getURL();
                                if ((url.startsWith("@") || url.startsWith("#") || url.startsWith("/")) && this.delegate != null) {
                                    this.delegate.didPressUrl(url);
                                }
                            } else if (clickableSpan2 instanceof URLSpan) {
                                Browser.openUrl(getContext(), ((URLSpan) this.pressedLink).getURL());
                            } else {
                                clickableSpan2.onClick(this);
                            }
                        } catch (Exception e3) {
                            FileLog.e(e3);
                        }
                        resetPressedLink();
                        result = true;
                    }
                }
            } else if (event.getAction() == 3) {
                resetPressedLink();
            }
        }
        return result || super.onTouchEvent(event);
    }

    @Override // android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        setMeasuredDimension(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), this.height + AndroidUtilities.dp(8.0f));
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        int x = (getWidth() - this.width) / 2;
        int y = AndroidUtilities.dp(4.0f);
        Theme.chat_msgInMediaShadowDrawable.setBounds(x, y, this.width + x, this.height + y);
        Theme.chat_msgInMediaShadowDrawable.draw(canvas);
        Theme.chat_msgInMediaDrawable.setBounds(x, y, this.width + x, this.height + y);
        Theme.chat_msgInMediaDrawable.draw(canvas);
        Theme.chat_msgTextPaint.setColor(Theme.getColor(Theme.key_chat_messageTextIn));
        Theme.chat_msgTextPaint.linkColor = Theme.getColor(Theme.key_chat_messageLinkIn);
        canvas.save();
        int iDp = AndroidUtilities.dp(11.0f) + x;
        this.textX = iDp;
        int iDp2 = AndroidUtilities.dp(11.0f) + y;
        this.textY = iDp2;
        canvas.translate(iDp, iDp2);
        if (this.pressedLink != null) {
            canvas.drawPath(this.urlPath, Theme.chat_urlPaint);
        }
        StaticLayout staticLayout = this.textLayout;
        if (staticLayout != null) {
            staticLayout.draw(canvas);
        }
        canvas.restore();
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        info.setText(this.textLayout.getText());
    }
}
