package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.graphics.Canvas;
import android.net.Uri;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.FrameLayout;
import androidx.core.net.MailTo;
import com.just.agentweb.DefaultWebClient;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.CheckBox2;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.LetterDrawable;
import im.uwrkaxlmjj.ui.components.LinkPath;
import java.util.ArrayList;
import java.util.Locale;

/* JADX INFO: loaded from: classes5.dex */
public class SharedLinkCell extends FrameLayout {
    private CheckBox2 checkBox;
    private boolean checkingForLongPress;
    private SharedLinkCellDelegate delegate;
    private int description2Y;
    private StaticLayout descriptionLayout;
    private StaticLayout descriptionLayout2;
    private TextPaint descriptionTextPaint;
    private int descriptionY;
    private boolean drawLinkImageView;
    private LetterDrawable letterDrawable;
    private ImageReceiver linkImageView;
    private ArrayList<StaticLayout> linkLayout;
    private boolean linkPreviewPressed;
    private int linkY;
    ArrayList<String> links;
    private MessageObject message;
    private boolean needDivider;
    private CheckForLongPress pendingCheckForLongPress;
    private CheckForTap pendingCheckForTap;
    private int pressCount;
    private int pressedLink;
    private StaticLayout titleLayout;
    private TextPaint titleTextPaint;
    private int titleY;
    private LinkPath urlPath;

    public interface SharedLinkCellDelegate {
        boolean canPerformActions();

        void needOpenWebView(TLRPC.WebPage webPage);

        void onLinkLongPress(String str);
    }

    static /* synthetic */ int access$104(SharedLinkCell x0) {
        int i = x0.pressCount + 1;
        x0.pressCount = i;
        return i;
    }

    private final class CheckForTap implements Runnable {
        private CheckForTap() {
        }

        @Override // java.lang.Runnable
        public void run() {
            if (SharedLinkCell.this.pendingCheckForLongPress == null) {
                SharedLinkCell sharedLinkCell = SharedLinkCell.this;
                sharedLinkCell.pendingCheckForLongPress = sharedLinkCell.new CheckForLongPress();
            }
            SharedLinkCell.this.pendingCheckForLongPress.currentPressCount = SharedLinkCell.access$104(SharedLinkCell.this);
            SharedLinkCell sharedLinkCell2 = SharedLinkCell.this;
            sharedLinkCell2.postDelayed(sharedLinkCell2.pendingCheckForLongPress, ViewConfiguration.getLongPressTimeout() - ViewConfiguration.getTapTimeout());
        }
    }

    class CheckForLongPress implements Runnable {
        public int currentPressCount;

        CheckForLongPress() {
        }

        @Override // java.lang.Runnable
        public void run() {
            if (SharedLinkCell.this.checkingForLongPress && SharedLinkCell.this.getParent() != null && this.currentPressCount == SharedLinkCell.this.pressCount) {
                SharedLinkCell.this.checkingForLongPress = false;
                SharedLinkCell.this.performHapticFeedback(0);
                if (SharedLinkCell.this.pressedLink >= 0) {
                    SharedLinkCell.this.delegate.onLinkLongPress(SharedLinkCell.this.links.get(SharedLinkCell.this.pressedLink));
                }
                MotionEvent event = MotionEvent.obtain(0L, 0L, 3, 0.0f, 0.0f, 0);
                SharedLinkCell.this.onTouchEvent(event);
                event.recycle();
            }
        }
    }

    protected void startCheckLongPress() {
        if (this.checkingForLongPress) {
            return;
        }
        this.checkingForLongPress = true;
        if (this.pendingCheckForTap == null) {
            this.pendingCheckForTap = new CheckForTap();
        }
        postDelayed(this.pendingCheckForTap, ViewConfiguration.getTapTimeout());
    }

    protected void cancelCheckLongPress() {
        this.checkingForLongPress = false;
        CheckForLongPress checkForLongPress = this.pendingCheckForLongPress;
        if (checkForLongPress != null) {
            removeCallbacks(checkForLongPress);
        }
        CheckForTap checkForTap = this.pendingCheckForTap;
        if (checkForTap != null) {
            removeCallbacks(checkForTap);
        }
    }

    public SharedLinkCell(Context context) {
        super(context);
        this.checkingForLongPress = false;
        this.pendingCheckForLongPress = null;
        this.pressCount = 0;
        this.pendingCheckForTap = null;
        this.links = new ArrayList<>();
        this.linkLayout = new ArrayList<>();
        this.titleY = AndroidUtilities.dp(10.0f);
        this.descriptionY = AndroidUtilities.dp(30.0f);
        this.description2Y = AndroidUtilities.dp(30.0f);
        setFocusable(true);
        LinkPath linkPath = new LinkPath();
        this.urlPath = linkPath;
        linkPath.setUseRoundRect(true);
        TextPaint textPaint = new TextPaint(1);
        this.titleTextPaint = textPaint;
        textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.titleTextPaint.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.descriptionTextPaint = new TextPaint(1);
        this.titleTextPaint.setTextSize(AndroidUtilities.dp(14.0f));
        this.descriptionTextPaint.setTextSize(AndroidUtilities.dp(14.0f));
        setWillNotDraw(false);
        ImageReceiver imageReceiver = new ImageReceiver(this);
        this.linkImageView = imageReceiver;
        imageReceiver.setRoundRadius(AndroidUtilities.dp(4.0f));
        this.letterDrawable = new LetterDrawable();
        CheckBox2 checkBox2 = new CheckBox2(context, 21);
        this.checkBox = checkBox2;
        checkBox2.setVisibility(4);
        this.checkBox.setColor(null, Theme.key_windowBackgroundWhite, Theme.key_checkboxCheck);
        this.checkBox.setDrawUnchecked(false);
        this.checkBox.setDrawBackgroundAsArc(2);
        addView(this.checkBox, LayoutHelper.createFrame(24.0f, 24.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 0.0f : 44.0f, 44.0f, LocaleController.isRTL ? 44.0f : 0.0f, 0.0f));
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int i, int i2) {
        String str;
        boolean z;
        String str2;
        String str3;
        String str4;
        int i3;
        String str5;
        int iLastIndexOf;
        this.drawLinkImageView = false;
        this.descriptionLayout = null;
        this.titleLayout = null;
        this.descriptionLayout2 = null;
        this.linkLayout.clear();
        this.links.clear();
        int size = (View.MeasureSpec.getSize(i) - AndroidUtilities.dp(AndroidUtilities.leftBaseline)) - AndroidUtilities.dp(8.0f);
        String str6 = null;
        String str7 = null;
        int i4 = 1;
        if ((this.message.messageOwner.media instanceof TLRPC.TL_messageMediaWebPage) && (this.message.messageOwner.media.webpage instanceof TLRPC.TL_webPage)) {
            TLRPC.WebPage webPage = this.message.messageOwner.media.webpage;
            if (this.message.photoThumbs == null && webPage.photo != null) {
                this.message.generateThumbs(true);
            }
            boolean z2 = (webPage.photo == null || this.message.photoThumbs == null) ? false : true;
            str6 = webPage.title;
            if (str6 == null) {
                str6 = webPage.site_name;
            }
            str7 = webPage.description;
            str = webPage.url;
            z = z2;
        } else {
            str = null;
            z = false;
        }
        MessageObject messageObject = this.message;
        if (messageObject != null && !messageObject.messageOwner.entities.isEmpty()) {
            int i5 = 0;
            String str8 = str7;
            String host = str6;
            String str9 = null;
            String str10 = str8;
            while (i5 < this.message.messageOwner.entities.size()) {
                TLRPC.MessageEntity messageEntity = this.message.messageOwner.entities.get(i5);
                if (messageEntity.length > 0 && messageEntity.offset >= 0 && messageEntity.offset < this.message.messageOwner.message.length()) {
                    if (messageEntity.offset + messageEntity.length > this.message.messageOwner.message.length()) {
                        messageEntity.length = this.message.messageOwner.message.length() - messageEntity.offset;
                    }
                    if (i5 == 0 && str != null && ((messageEntity.offset != 0 || messageEntity.length != this.message.messageOwner.message.length()) && (this.message.messageOwner.entities.size() != i4 || str10 == null))) {
                        str5 = this.message.messageOwner.message;
                    } else {
                        str5 = str9;
                    }
                    String strSubstring = null;
                    try {
                        if ((messageEntity instanceof TLRPC.TL_messageEntityTextUrl) || (messageEntity instanceof TLRPC.TL_messageEntityUrl)) {
                            if (messageEntity instanceof TLRPC.TL_messageEntityUrl) {
                                strSubstring = this.message.messageOwner.message.substring(messageEntity.offset, messageEntity.offset + messageEntity.length);
                            } else {
                                strSubstring = messageEntity.url;
                            }
                            if (host == null || host.length() == 0) {
                                host = Uri.parse(strSubstring).getHost();
                                if (host == null) {
                                    host = strSubstring;
                                }
                                if (host != null && (iLastIndexOf = host.lastIndexOf(46)) >= 0) {
                                    String strSubstring2 = host.substring(0, iLastIndexOf);
                                    int iLastIndexOf2 = strSubstring2.lastIndexOf(46);
                                    if (iLastIndexOf2 >= 0) {
                                        strSubstring2 = strSubstring2.substring(iLastIndexOf2 + 1);
                                    }
                                    host = strSubstring2.substring(0, 1).toUpperCase() + strSubstring2.substring(1);
                                }
                                if (messageEntity.offset != 0 || messageEntity.length != this.message.messageOwner.message.length()) {
                                    str10 = this.message.messageOwner.message;
                                }
                            }
                        } else if ((messageEntity instanceof TLRPC.TL_messageEntityEmail) && (host == null || host.length() == 0)) {
                            strSubstring = MailTo.MAILTO_SCHEME + this.message.messageOwner.message.substring(messageEntity.offset, messageEntity.offset + messageEntity.length);
                            host = this.message.messageOwner.message.substring(messageEntity.offset, messageEntity.offset + messageEntity.length);
                            if (messageEntity.offset != 0 || messageEntity.length != this.message.messageOwner.message.length()) {
                                str10 = this.message.messageOwner.message;
                            }
                        }
                        if (strSubstring != null) {
                            if (strSubstring.toLowerCase().indexOf("http") != 0 && strSubstring.toLowerCase().indexOf("mailto") != 0) {
                                this.links.add(DefaultWebClient.HTTP_SCHEME + strSubstring);
                            } else {
                                this.links.add(strSubstring);
                            }
                        }
                        str9 = str5;
                    } catch (Exception e) {
                        FileLog.e(e);
                        str9 = str5;
                    }
                }
                i5++;
                i4 = 1;
            }
            str4 = str9;
            str2 = host;
            str3 = str10;
        } else {
            str2 = str6;
            str3 = str7;
            str4 = null;
        }
        if (str != null && this.links.isEmpty()) {
            this.links.add(str);
        }
        if (str2 != null) {
            try {
                StaticLayout staticLayoutGenerateStaticLayout = ChatMessageCell.generateStaticLayout(str2, this.titleTextPaint, size, size, 0, 3);
                this.titleLayout = staticLayoutGenerateStaticLayout;
                if (staticLayoutGenerateStaticLayout.getLineCount() > 0) {
                    this.descriptionY = this.titleY + this.titleLayout.getLineBottom(this.titleLayout.getLineCount() - 1) + AndroidUtilities.dp(4.0f);
                }
            } catch (Exception e2) {
                FileLog.e(e2);
            }
            this.letterDrawable.setTitle(str2);
        }
        this.description2Y = this.descriptionY;
        StaticLayout staticLayout = this.titleLayout;
        int iMax = Math.max(1, 4 - (staticLayout != null ? staticLayout.getLineCount() : 0));
        if (str3 != null) {
            try {
                StaticLayout staticLayoutGenerateStaticLayout2 = ChatMessageCell.generateStaticLayout(str3, this.descriptionTextPaint, size, size, 0, iMax);
                this.descriptionLayout = staticLayoutGenerateStaticLayout2;
                if (staticLayoutGenerateStaticLayout2.getLineCount() > 0) {
                    this.description2Y = this.descriptionY + this.descriptionLayout.getLineBottom(this.descriptionLayout.getLineCount() - 1) + AndroidUtilities.dp(5.0f);
                }
            } catch (Exception e3) {
                FileLog.e(e3);
            }
        }
        if (str4 != null) {
            try {
                this.descriptionLayout2 = ChatMessageCell.generateStaticLayout(str4, this.descriptionTextPaint, size, size, 0, iMax);
                if (this.descriptionLayout != null) {
                    this.description2Y += AndroidUtilities.dp(10.0f);
                }
            } catch (Exception e4) {
                FileLog.e(e4);
            }
        }
        if (!this.links.isEmpty()) {
            int i6 = 0;
            while (i6 < this.links.size()) {
                try {
                    i3 = i6;
                } catch (Exception e5) {
                    e = e5;
                    i3 = i6;
                }
                try {
                    StaticLayout staticLayout2 = new StaticLayout(TextUtils.ellipsize(this.links.get(i6).replace('\n', ' '), this.descriptionTextPaint, Math.min((int) Math.ceil(this.descriptionTextPaint.measureText(r0)), size), TextUtils.TruncateAt.MIDDLE), this.descriptionTextPaint, size, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                    this.linkY = this.description2Y;
                    if (this.descriptionLayout2 != null && this.descriptionLayout2.getLineCount() != 0) {
                        this.linkY += this.descriptionLayout2.getLineBottom(this.descriptionLayout2.getLineCount() - 1) + AndroidUtilities.dp(5.0f);
                    }
                    this.linkLayout.add(staticLayout2);
                } catch (Exception e6) {
                    e = e6;
                    FileLog.e(e);
                }
                i6 = i3 + 1;
            }
        }
        int iDp = AndroidUtilities.dp(52.0f);
        int size2 = LocaleController.isRTL ? (View.MeasureSpec.getSize(i) - AndroidUtilities.dp(10.0f)) - iDp : AndroidUtilities.dp(10.0f);
        this.letterDrawable.setBounds(size2, AndroidUtilities.dp(11.0f), size2 + iDp, AndroidUtilities.dp(63.0f));
        if (z) {
            TLRPC.PhotoSize closestPhotoSizeWithSize = FileLoader.getClosestPhotoSizeWithSize(this.message.photoThumbs, iDp, true);
            TLRPC.PhotoSize closestPhotoSizeWithSize2 = FileLoader.getClosestPhotoSizeWithSize(this.message.photoThumbs, 80);
            if (closestPhotoSizeWithSize2 == closestPhotoSizeWithSize) {
                closestPhotoSizeWithSize2 = null;
            }
            closestPhotoSizeWithSize.size = -1;
            if (closestPhotoSizeWithSize2 != null) {
                closestPhotoSizeWithSize2.size = -1;
            }
            this.linkImageView.setImageCoords(size2, AndroidUtilities.dp(11.0f), iDp, iDp);
            FileLoader.getAttachFileName(closestPhotoSizeWithSize);
            this.linkImageView.setImage(ImageLocation.getForObject(closestPhotoSizeWithSize, this.message.photoThumbsObject), String.format(Locale.US, "%d_%d", Integer.valueOf(iDp), Integer.valueOf(iDp)), ImageLocation.getForObject(closestPhotoSizeWithSize2, this.message.photoThumbsObject), String.format(Locale.US, "%d_%d_b", Integer.valueOf(iDp), Integer.valueOf(iDp)), 0, null, this.message, 0);
            this.drawLinkImageView = true;
        }
        int lineBottom = 0;
        StaticLayout staticLayout3 = this.titleLayout;
        if (staticLayout3 != null && staticLayout3.getLineCount() != 0) {
            StaticLayout staticLayout4 = this.titleLayout;
            lineBottom = 0 + staticLayout4.getLineBottom(staticLayout4.getLineCount() - 1) + AndroidUtilities.dp(4.0f);
        }
        StaticLayout staticLayout5 = this.descriptionLayout;
        if (staticLayout5 != null && staticLayout5.getLineCount() != 0) {
            StaticLayout staticLayout6 = this.descriptionLayout;
            lineBottom += staticLayout6.getLineBottom(staticLayout6.getLineCount() - 1) + AndroidUtilities.dp(5.0f);
        }
        StaticLayout staticLayout7 = this.descriptionLayout2;
        if (staticLayout7 != null && staticLayout7.getLineCount() != 0) {
            StaticLayout staticLayout8 = this.descriptionLayout2;
            lineBottom += staticLayout8.getLineBottom(staticLayout8.getLineCount() - 1) + AndroidUtilities.dp(5.0f);
            if (this.descriptionLayout != null) {
                lineBottom += AndroidUtilities.dp(10.0f);
            }
        }
        for (int i7 = 0; i7 < this.linkLayout.size(); i7++) {
            StaticLayout staticLayout9 = this.linkLayout.get(i7);
            if (staticLayout9.getLineCount() > 0) {
                lineBottom += staticLayout9.getLineBottom(staticLayout9.getLineCount() - 1);
            }
        }
        this.checkBox.measure(View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(24.0f), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(24.0f), 1073741824));
        setMeasuredDimension(View.MeasureSpec.getSize(i), Math.max(AndroidUtilities.dp(76.0f), AndroidUtilities.dp(17.0f) + lineBottom) + (this.needDivider ? 1 : 0));
    }

    public void setLink(MessageObject messageObject, boolean divider) {
        this.needDivider = divider;
        resetPressedLink();
        this.message = messageObject;
        requestLayout();
    }

    public void setDelegate(SharedLinkCellDelegate sharedLinkCellDelegate) {
        this.delegate = sharedLinkCellDelegate;
    }

    public MessageObject getMessage() {
        return this.message;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (this.drawLinkImageView) {
            this.linkImageView.onDetachedFromWindow();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.drawLinkImageView) {
            this.linkImageView.onAttachedToWindow();
        }
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        SharedLinkCellDelegate sharedLinkCellDelegate;
        boolean result = false;
        if (this.message != null && !this.linkLayout.isEmpty() && (sharedLinkCellDelegate = this.delegate) != null && sharedLinkCellDelegate.canPerformActions()) {
            if (event.getAction() == 0 || (this.linkPreviewPressed && event.getAction() == 1)) {
                int x = (int) event.getX();
                int y = (int) event.getY();
                boolean ok = false;
                int a = 0;
                int offset = 0;
                while (true) {
                    if (a >= this.linkLayout.size()) {
                        break;
                    }
                    StaticLayout layout = this.linkLayout.get(a);
                    if (layout.getLineCount() > 0) {
                        int height = layout.getLineBottom(layout.getLineCount() - 1);
                        int linkPosX = AndroidUtilities.dp(LocaleController.isRTL ? 8.0f : AndroidUtilities.leftBaseline);
                        if (x >= linkPosX + layout.getLineLeft(0) && x <= linkPosX + layout.getLineWidth(0)) {
                            int i = this.linkY;
                            if (y >= i + offset && y <= i + offset + height) {
                                ok = true;
                                if (event.getAction() == 0) {
                                    resetPressedLink();
                                    this.pressedLink = a;
                                    this.linkPreviewPressed = true;
                                    startCheckLongPress();
                                    try {
                                        this.urlPath.setCurrentLayout(layout, 0, 0.0f);
                                        layout.getSelectionPath(0, layout.getText().length(), this.urlPath);
                                    } catch (Exception e) {
                                        FileLog.e(e);
                                    }
                                    result = true;
                                } else if (this.linkPreviewPressed) {
                                    try {
                                        TLRPC.WebPage webPage = (this.pressedLink != 0 || this.message.messageOwner.media == null) ? null : this.message.messageOwner.media.webpage;
                                        if (webPage == null || webPage.embed_url == null || webPage.embed_url.length() == 0) {
                                            Browser.openUrl(getContext(), this.links.get(this.pressedLink));
                                        } else {
                                            this.delegate.needOpenWebView(webPage);
                                        }
                                    } catch (Exception e2) {
                                        FileLog.e(e2);
                                    }
                                    resetPressedLink();
                                    result = true;
                                }
                            }
                        }
                        offset += height;
                    }
                    a++;
                }
                if (!ok) {
                    resetPressedLink();
                }
            } else if (event.getAction() == 3) {
                resetPressedLink();
            }
        } else {
            resetPressedLink();
        }
        return result || super.onTouchEvent(event);
    }

    public String getLink(int num) {
        if (num < 0 || num >= this.links.size()) {
            return null;
        }
        return this.links.get(num);
    }

    protected void resetPressedLink() {
        this.pressedLink = -1;
        this.linkPreviewPressed = false;
        cancelCheckLongPress();
        invalidate();
    }

    public void setChecked(boolean checked, boolean animated) {
        if (this.checkBox.getVisibility() != 0) {
            this.checkBox.setVisibility(0);
        }
        this.checkBox.setChecked(checked, animated);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        if (this.titleLayout != null) {
            canvas.save();
            canvas.translate(AndroidUtilities.dp(LocaleController.isRTL ? 8.0f : AndroidUtilities.leftBaseline), this.titleY);
            this.titleLayout.draw(canvas);
            canvas.restore();
        }
        if (this.descriptionLayout != null) {
            this.descriptionTextPaint.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            canvas.save();
            canvas.translate(AndroidUtilities.dp(LocaleController.isRTL ? 8.0f : AndroidUtilities.leftBaseline), this.descriptionY);
            this.descriptionLayout.draw(canvas);
            canvas.restore();
        }
        if (this.descriptionLayout2 != null) {
            this.descriptionTextPaint.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            canvas.save();
            canvas.translate(AndroidUtilities.dp(LocaleController.isRTL ? 8.0f : AndroidUtilities.leftBaseline), this.description2Y);
            this.descriptionLayout2.draw(canvas);
            canvas.restore();
        }
        if (!this.linkLayout.isEmpty()) {
            this.descriptionTextPaint.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteLinkText));
            int offset = 0;
            for (int a = 0; a < this.linkLayout.size(); a++) {
                StaticLayout layout = this.linkLayout.get(a);
                if (layout.getLineCount() > 0) {
                    canvas.save();
                    canvas.translate(AndroidUtilities.dp(LocaleController.isRTL ? 8.0f : AndroidUtilities.leftBaseline), this.linkY + offset);
                    if (this.pressedLink == a) {
                        canvas.drawPath(this.urlPath, Theme.linkSelectionPaint);
                    }
                    layout.draw(canvas);
                    canvas.restore();
                    offset += layout.getLineBottom(layout.getLineCount() - 1);
                }
            }
        }
        this.letterDrawable.draw(canvas);
        if (this.drawLinkImageView) {
            this.linkImageView.draw(canvas);
        }
        if (this.needDivider) {
            if (LocaleController.isRTL) {
                canvas.drawLine(0.0f, getMeasuredHeight() - 1, getMeasuredWidth() - AndroidUtilities.dp(AndroidUtilities.leftBaseline), getMeasuredHeight() - 1, Theme.dividerPaint);
            } else {
                canvas.drawLine(AndroidUtilities.dp(AndroidUtilities.leftBaseline), getMeasuredHeight() - 1, getMeasuredWidth(), getMeasuredHeight() - 1, Theme.dividerPaint);
            }
        }
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        StringBuilder sb = new StringBuilder();
        StaticLayout staticLayout = this.titleLayout;
        if (staticLayout != null) {
            sb.append(staticLayout.getText());
        }
        if (this.descriptionLayout != null) {
            sb.append(", ");
            sb.append(this.descriptionLayout.getText());
        }
        if (this.descriptionLayout2 != null) {
            sb.append(", ");
            sb.append(this.descriptionLayout2.getText());
        }
        if (this.checkBox.isChecked()) {
            info.setChecked(true);
            info.setCheckable(true);
        }
    }
}
