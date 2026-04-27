package im.uwrkaxlmjj.ui.cells;

import android.content.Context;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.AccelerateInterpolator;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.DownloadController;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.WebFile;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LetterDrawable;
import im.uwrkaxlmjj.ui.components.RadialProgress2;
import java.io.File;
import java.util.ArrayList;
import java.util.Locale;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ContextLinkCell extends View implements DownloadController.FileDownloadProgressListener {
    private static final int DOCUMENT_ATTACH_TYPE_AUDIO = 3;
    private static final int DOCUMENT_ATTACH_TYPE_DOCUMENT = 1;
    private static final int DOCUMENT_ATTACH_TYPE_GEO = 8;
    private static final int DOCUMENT_ATTACH_TYPE_GIF = 2;
    private static final int DOCUMENT_ATTACH_TYPE_MUSIC = 5;
    private static final int DOCUMENT_ATTACH_TYPE_NONE = 0;
    private static final int DOCUMENT_ATTACH_TYPE_PHOTO = 7;
    private static final int DOCUMENT_ATTACH_TYPE_STICKER = 6;
    private static final int DOCUMENT_ATTACH_TYPE_VIDEO = 4;
    private static AccelerateInterpolator interpolator = new AccelerateInterpolator(0.5f);
    private int TAG;
    private boolean buttonPressed;
    private int buttonState;
    private boolean canPreviewGif;
    private int currentAccount;
    private MessageObject currentMessageObject;
    private TLRPC.PhotoSize currentPhotoObject;
    private ContextLinkCellDelegate delegate;
    private StaticLayout descriptionLayout;
    private int descriptionY;
    private TLRPC.Document documentAttach;
    private int documentAttachType;
    private boolean drawLinkImageView;
    private TLRPC.BotInlineResult inlineResult;
    private long lastUpdateTime;
    private LetterDrawable letterDrawable;
    private ImageReceiver linkImageView;
    private StaticLayout linkLayout;
    private int linkY;
    private boolean mediaWebpage;
    private boolean needDivider;
    private boolean needShadow;
    private Object parentObject;
    private TLRPC.Photo photoAttach;
    private RadialProgress2 radialProgress;
    private float scale;
    private boolean scaled;
    private StaticLayout titleLayout;
    private int titleY;

    public interface ContextLinkCellDelegate {
        void didPressedImage(ContextLinkCell contextLinkCell);
    }

    public ContextLinkCell(Context context) {
        super(context);
        this.currentAccount = UserConfig.selectedAccount;
        this.titleY = AndroidUtilities.dp(7.0f);
        this.descriptionY = AndroidUtilities.dp(27.0f);
        ImageReceiver imageReceiver = new ImageReceiver(this);
        this.linkImageView = imageReceiver;
        imageReceiver.setLayerNum(1);
        this.linkImageView.setUseSharedAnimationQueue(true);
        this.letterDrawable = new LetterDrawable();
        this.radialProgress = new RadialProgress2(this);
        this.TAG = DownloadController.getInstance(this.currentAccount).generateObserverTag();
        setFocusable(true);
    }

    @Override // android.view.View
    protected void onMeasure(int i, int i2) {
        ArrayList arrayList;
        ArrayList arrayList2;
        boolean z;
        String str;
        float f;
        int iDp;
        TLRPC.BotInlineResult botInlineResult;
        char c;
        char c2;
        this.drawLinkImageView = false;
        this.descriptionLayout = null;
        this.titleLayout = null;
        this.linkLayout = null;
        this.currentPhotoObject = null;
        this.linkY = AndroidUtilities.dp(27.0f);
        if (this.inlineResult == null && this.documentAttach == null) {
            setMeasuredDimension(AndroidUtilities.dp(100.0f), AndroidUtilities.dp(100.0f));
            return;
        }
        int size = View.MeasureSpec.getSize(i);
        int iDp2 = (size - AndroidUtilities.dp(AndroidUtilities.leftBaseline)) - AndroidUtilities.dp(8.0f);
        TLRPC.PhotoSize closestPhotoSizeWithSize = null;
        WebFile webFileCreateWithWebDocument = null;
        TLRPC.TL_webDocument tL_webDocument = null;
        if (this.documentAttach != null) {
            arrayList = new ArrayList(this.documentAttach.thumbs);
        } else {
            TLRPC.BotInlineResult botInlineResult2 = this.inlineResult;
            if (botInlineResult2 != null && botInlineResult2.photo != null) {
                arrayList = new ArrayList(this.inlineResult.photo.sizes);
            } else {
                arrayList = null;
            }
        }
        if (this.mediaWebpage || (botInlineResult = this.inlineResult) == null) {
            arrayList2 = arrayList;
            z = true;
        } else {
            if (botInlineResult.title != null) {
                try {
                    this.titleLayout = new StaticLayout(TextUtils.ellipsize(Emoji.replaceEmoji(this.inlineResult.title.replace('\n', ' '), Theme.chat_contextResult_titleTextPaint.getFontMetricsInt(), AndroidUtilities.dp(15.0f), false), Theme.chat_contextResult_titleTextPaint, Math.min((int) Math.ceil(Theme.chat_contextResult_titleTextPaint.measureText(this.inlineResult.title)), iDp2), TextUtils.TruncateAt.END), Theme.chat_contextResult_titleTextPaint, iDp2 + AndroidUtilities.dp(4.0f), Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                } catch (Exception e) {
                    FileLog.e(e);
                }
                this.letterDrawable.setTitle(this.inlineResult.title);
            }
            if (this.inlineResult.description == null) {
                c = ' ';
                c2 = '\n';
            } else {
                try {
                    c2 = '\n';
                    c = ' ';
                } catch (Exception e2) {
                    e = e2;
                    c = ' ';
                    c2 = '\n';
                }
                try {
                    StaticLayout staticLayoutGenerateStaticLayout = ChatMessageCell.generateStaticLayout(Emoji.replaceEmoji(this.inlineResult.description, Theme.chat_contextResult_descriptionTextPaint.getFontMetricsInt(), AndroidUtilities.dp(13.0f), false), Theme.chat_contextResult_descriptionTextPaint, iDp2, iDp2, 0, 3);
                    this.descriptionLayout = staticLayoutGenerateStaticLayout;
                    if (staticLayoutGenerateStaticLayout.getLineCount() > 0) {
                        this.linkY = this.descriptionY + this.descriptionLayout.getLineBottom(this.descriptionLayout.getLineCount() - 1) + AndroidUtilities.dp(1.0f);
                    }
                } catch (Exception e3) {
                    e = e3;
                    FileLog.e(e);
                }
            }
            if (this.inlineResult.url == null) {
                arrayList2 = arrayList;
                z = true;
            } else {
                try {
                    CharSequence charSequenceEllipsize = TextUtils.ellipsize(this.inlineResult.url.replace(c2, c), Theme.chat_contextResult_descriptionTextPaint, Math.min((int) Math.ceil(Theme.chat_contextResult_descriptionTextPaint.measureText(this.inlineResult.url)), iDp2), TextUtils.TruncateAt.MIDDLE);
                    z = true;
                    arrayList2 = arrayList;
                    try {
                        this.linkLayout = new StaticLayout(charSequenceEllipsize, Theme.chat_contextResult_descriptionTextPaint, iDp2, Layout.Alignment.ALIGN_NORMAL, 1.0f, 0.0f, false);
                    } catch (Exception e4) {
                        e = e4;
                        FileLog.e(e);
                    }
                } catch (Exception e5) {
                    e = e5;
                    arrayList2 = arrayList;
                    z = true;
                }
            }
        }
        String str2 = null;
        TLRPC.Document document = this.documentAttach;
        if (document != null) {
            if (MessageObject.isGifDocument(document)) {
                this.currentPhotoObject = FileLoader.getClosestPhotoSizeWithSize(this.documentAttach.thumbs, 90);
            } else if (MessageObject.isStickerDocument(this.documentAttach) || MessageObject.isAnimatedStickerDocument(this.documentAttach)) {
                this.currentPhotoObject = FileLoader.getClosestPhotoSizeWithSize(this.documentAttach.thumbs, 90);
                str2 = "webp";
            } else {
                int i3 = this.documentAttachType;
                if (i3 != 5 && i3 != 3) {
                    this.currentPhotoObject = FileLoader.getClosestPhotoSizeWithSize(this.documentAttach.thumbs, 90);
                }
            }
        } else {
            TLRPC.BotInlineResult botInlineResult3 = this.inlineResult;
            if (botInlineResult3 != null && botInlineResult3.photo != null) {
                this.currentPhotoObject = FileLoader.getClosestPhotoSizeWithSize(arrayList2, AndroidUtilities.getPhotoSize(), z);
                closestPhotoSizeWithSize = FileLoader.getClosestPhotoSizeWithSize(arrayList2, 80);
                if (closestPhotoSizeWithSize == this.currentPhotoObject) {
                    closestPhotoSizeWithSize = null;
                }
            }
        }
        TLRPC.BotInlineResult botInlineResult4 = this.inlineResult;
        if (botInlineResult4 != null) {
            if ((botInlineResult4.content instanceof TLRPC.TL_webDocument) && this.inlineResult.type != null) {
                if (this.inlineResult.type.startsWith("gif")) {
                    tL_webDocument = (TLRPC.TL_webDocument) this.inlineResult.content;
                    this.documentAttachType = 2;
                } else if (this.inlineResult.type.equals("photo")) {
                    tL_webDocument = this.inlineResult.thumb instanceof TLRPC.TL_webDocument ? (TLRPC.TL_webDocument) this.inlineResult.thumb : (TLRPC.TL_webDocument) this.inlineResult.content;
                }
            }
            if (tL_webDocument == null && (this.inlineResult.thumb instanceof TLRPC.TL_webDocument)) {
                tL_webDocument = (TLRPC.TL_webDocument) this.inlineResult.thumb;
            }
            if (tL_webDocument == null && this.currentPhotoObject == null && closestPhotoSizeWithSize == null && ((this.inlineResult.send_message instanceof TLRPC.TL_botInlineMessageMediaVenue) || (this.inlineResult.send_message instanceof TLRPC.TL_botInlineMessageMediaGeo))) {
                double d = this.inlineResult.send_message.geo.lat;
                double d2 = this.inlineResult.send_message.geo._long;
                if (MessagesController.getInstance(this.currentAccount).mapProvider == 2) {
                    webFileCreateWithWebDocument = WebFile.createWithGeoPoint(this.inlineResult.send_message.geo, 72, 72, 15, Math.min(2, (int) Math.ceil(AndroidUtilities.density)));
                }
            }
            if (tL_webDocument != null) {
                webFileCreateWithWebDocument = WebFile.createWithWebDocument(tL_webDocument);
            }
        }
        int i4 = 0;
        int i5 = 0;
        if (this.documentAttach != null) {
            for (int i6 = 0; i6 < this.documentAttach.attributes.size(); i6++) {
                TLRPC.DocumentAttribute documentAttribute = this.documentAttach.attributes.get(i6);
                if ((documentAttribute instanceof TLRPC.TL_documentAttributeImageSize) || (documentAttribute instanceof TLRPC.TL_documentAttributeVideo)) {
                    i4 = documentAttribute.w;
                    i5 = documentAttribute.h;
                    break;
                }
            }
        }
        if (i4 == 0 || i5 == 0) {
            if (this.currentPhotoObject != null) {
                if (closestPhotoSizeWithSize != null) {
                    closestPhotoSizeWithSize.size = -1;
                }
                i4 = this.currentPhotoObject.w;
                i5 = this.currentPhotoObject.h;
            } else {
                TLRPC.BotInlineResult botInlineResult5 = this.inlineResult;
                if (botInlineResult5 != null) {
                    int[] inlineResultWidthAndHeight = MessageObject.getInlineResultWidthAndHeight(botInlineResult5);
                    i4 = inlineResultWidthAndHeight[0];
                    i5 = inlineResultWidthAndHeight[1];
                }
            }
        }
        if (i4 == 0 || i5 == 0) {
            int iDp3 = AndroidUtilities.dp(80.0f);
            i5 = iDp3;
            i4 = iDp3;
        }
        if (this.documentAttach != null || this.currentPhotoObject != null || webFileCreateWithWebDocument != null || 0 != 0) {
            String str3 = "52_52_b";
            if (this.mediaWebpage) {
                int iDp4 = (int) (i4 / (i5 / AndroidUtilities.dp(80.0f)));
                if (this.documentAttachType == 2) {
                    String str4 = String.format(Locale.US, "%d_%d_b", Integer.valueOf((int) (iDp4 / AndroidUtilities.density)), 80);
                    str = str4;
                    str3 = str4;
                } else {
                    str = String.format(Locale.US, "%d_%d", Integer.valueOf((int) (iDp4 / AndroidUtilities.density)), 80);
                    str3 = str + "_b";
                }
            } else {
                str = "52_52";
            }
            this.linkImageView.setAspectFit(this.documentAttachType == 6);
            if (this.documentAttachType == 2) {
                TLRPC.Document document2 = this.documentAttach;
                if (document2 != null) {
                    this.linkImageView.setImage(ImageLocation.getForDocument(document2), null, ImageLocation.getForDocument(this.currentPhotoObject, this.documentAttach), str, this.documentAttach.size, str2, this.parentObject, 0);
                } else if (webFileCreateWithWebDocument != null) {
                    this.linkImageView.setImage(ImageLocation.getForWebFile(webFileCreateWithWebDocument), null, ImageLocation.getForPhoto(this.currentPhotoObject, this.photoAttach), str, -1, str2, this.parentObject, 1);
                } else {
                    this.linkImageView.setImage(ImageLocation.getForPath(null), null, ImageLocation.getForPhoto(this.currentPhotoObject, this.photoAttach), str, -1, str2, this.parentObject, 1);
                }
            } else if (this.currentPhotoObject != null) {
                if (MessageObject.canAutoplayAnimatedSticker(this.documentAttach)) {
                    this.linkImageView.setImage(ImageLocation.getForDocument(this.documentAttach), "80_80", ImageLocation.getForDocument(this.currentPhotoObject, this.documentAttach), str3, this.currentPhotoObject.size, null, this.parentObject, 0);
                } else {
                    TLRPC.Document document3 = this.documentAttach;
                    if (document3 != null) {
                        this.linkImageView.setImage(ImageLocation.getForDocument(this.currentPhotoObject, document3), str, ImageLocation.getForPhoto(closestPhotoSizeWithSize, this.photoAttach), str3, this.currentPhotoObject.size, str2, this.parentObject, 0);
                    } else {
                        this.linkImageView.setImage(ImageLocation.getForPhoto(this.currentPhotoObject, this.photoAttach), str, ImageLocation.getForPhoto(closestPhotoSizeWithSize, this.photoAttach), str3, this.currentPhotoObject.size, str2, this.parentObject, 0);
                    }
                }
            } else if (webFileCreateWithWebDocument != null) {
                this.linkImageView.setImage(ImageLocation.getForWebFile(webFileCreateWithWebDocument), str, ImageLocation.getForPhoto(closestPhotoSizeWithSize, this.photoAttach), str3, -1, str2, this.parentObject, 1);
            } else {
                this.linkImageView.setImage(ImageLocation.getForPath(null), str, ImageLocation.getForPhoto(closestPhotoSizeWithSize, this.photoAttach), str3, -1, str2, this.parentObject, 1);
            }
            this.drawLinkImageView = true;
        }
        if (this.mediaWebpage) {
            int size2 = View.MeasureSpec.getSize(i2);
            if (size2 == 0) {
                size2 = AndroidUtilities.dp(100.0f);
            }
            setMeasuredDimension(size, size2);
            int iDp5 = (size - AndroidUtilities.dp(24.0f)) / 2;
            int iDp6 = (size2 - AndroidUtilities.dp(24.0f)) / 2;
            this.radialProgress.setProgressRect(iDp5, iDp6, AndroidUtilities.dp(24.0f) + iDp5, AndroidUtilities.dp(24.0f) + iDp6);
            this.radialProgress.setCircleRadius(AndroidUtilities.dp(12.0f));
            this.linkImageView.setImageCoords(0, 0, size, size2);
            return;
        }
        int lineBottom = 0;
        StaticLayout staticLayout = this.titleLayout;
        if (staticLayout != null && staticLayout.getLineCount() != 0) {
            StaticLayout staticLayout2 = this.titleLayout;
            lineBottom = 0 + staticLayout2.getLineBottom(staticLayout2.getLineCount() - 1);
        }
        StaticLayout staticLayout3 = this.descriptionLayout;
        if (staticLayout3 != null && staticLayout3.getLineCount() != 0) {
            StaticLayout staticLayout4 = this.descriptionLayout;
            lineBottom += staticLayout4.getLineBottom(staticLayout4.getLineCount() - 1);
        }
        StaticLayout staticLayout5 = this.linkLayout;
        if (staticLayout5 != null && staticLayout5.getLineCount() > 0) {
            StaticLayout staticLayout6 = this.linkLayout;
            lineBottom += staticLayout6.getLineBottom(staticLayout6.getLineCount() - 1);
        }
        setMeasuredDimension(View.MeasureSpec.getSize(i), Math.max(AndroidUtilities.dp(68.0f), AndroidUtilities.dp(16.0f) + Math.max(AndroidUtilities.dp(52.0f), lineBottom)) + (this.needDivider ? 1 : 0));
        int iDp7 = AndroidUtilities.dp(52.0f);
        if (LocaleController.isRTL) {
            f = 8.0f;
            iDp = (View.MeasureSpec.getSize(i) - AndroidUtilities.dp(8.0f)) - iDp7;
        } else {
            f = 8.0f;
            iDp = AndroidUtilities.dp(8.0f);
        }
        this.letterDrawable.setBounds(iDp, AndroidUtilities.dp(f), iDp + iDp7, AndroidUtilities.dp(60.0f));
        this.linkImageView.setImageCoords(iDp, AndroidUtilities.dp(f), iDp7, iDp7);
        int i7 = this.documentAttachType;
        if (i7 == 3 || i7 == 5) {
            this.radialProgress.setCircleRadius(AndroidUtilities.dp(24.0f));
            this.radialProgress.setProgressRect(AndroidUtilities.dp(4.0f) + iDp, AndroidUtilities.dp(12.0f), AndroidUtilities.dp(48.0f) + iDp, AndroidUtilities.dp(56.0f));
        }
    }

    private void setAttachType() {
        this.currentMessageObject = null;
        this.documentAttachType = 0;
        TLRPC.Document document = this.documentAttach;
        if (document != null) {
            if (MessageObject.isGifDocument(document)) {
                this.documentAttachType = 2;
            } else if (MessageObject.isStickerDocument(this.documentAttach) || MessageObject.isAnimatedStickerDocument(this.documentAttach)) {
                this.documentAttachType = 6;
            } else if (MessageObject.isMusicDocument(this.documentAttach)) {
                this.documentAttachType = 5;
            } else if (MessageObject.isVoiceDocument(this.documentAttach)) {
                this.documentAttachType = 3;
            }
        } else {
            TLRPC.BotInlineResult botInlineResult = this.inlineResult;
            if (botInlineResult != null) {
                if (botInlineResult.photo != null) {
                    this.documentAttachType = 7;
                } else if (this.inlineResult.type.equals("audio")) {
                    this.documentAttachType = 5;
                } else if (this.inlineResult.type.equals("voice")) {
                    this.documentAttachType = 3;
                }
            }
        }
        int i = this.documentAttachType;
        if (i == 3 || i == 5) {
            TLRPC.TL_message message = new TLRPC.TL_message();
            message.out = true;
            message.id = -Utilities.random.nextInt();
            message.to_id = new TLRPC.TL_peerUser();
            TLRPC.Peer peer = message.to_id;
            int clientUserId = UserConfig.getInstance(this.currentAccount).getClientUserId();
            message.from_id = clientUserId;
            peer.user_id = clientUserId;
            message.date = (int) (System.currentTimeMillis() / 1000);
            message.message = "";
            message.media = new TLRPC.TL_messageMediaDocument();
            message.media.flags |= 3;
            message.media.document = new TLRPC.TL_document();
            message.media.document.file_reference = new byte[0];
            message.flags |= 768;
            if (this.documentAttach != null) {
                message.media.document = this.documentAttach;
                message.attachPath = "";
            } else {
                String ext = ImageLoader.getHttpUrlExtension(this.inlineResult.content.url, this.documentAttachType == 5 ? "mp3" : "ogg");
                message.media.document.id = 0L;
                message.media.document.access_hash = 0L;
                message.media.document.date = message.date;
                message.media.document.mime_type = "audio/" + ext;
                message.media.document.size = 0;
                message.media.document.dc_id = 0;
                TLRPC.TL_documentAttributeAudio attributeAudio = new TLRPC.TL_documentAttributeAudio();
                attributeAudio.duration = MessageObject.getInlineResultDuration(this.inlineResult);
                attributeAudio.title = this.inlineResult.title != null ? this.inlineResult.title : "";
                attributeAudio.performer = this.inlineResult.description != null ? this.inlineResult.description : "";
                attributeAudio.flags |= 3;
                if (this.documentAttachType == 3) {
                    attributeAudio.voice = true;
                }
                message.media.document.attributes.add(attributeAudio);
                TLRPC.TL_documentAttributeFilename fileName = new TLRPC.TL_documentAttributeFilename();
                StringBuilder sb = new StringBuilder();
                sb.append(Utilities.MD5(this.inlineResult.content.url));
                sb.append(".");
                sb.append(ImageLoader.getHttpUrlExtension(this.inlineResult.content.url, this.documentAttachType == 5 ? "mp3" : "ogg"));
                fileName.file_name = sb.toString();
                message.media.document.attributes.add(fileName);
                File directory = FileLoader.getDirectory(4);
                StringBuilder sb2 = new StringBuilder();
                sb2.append(Utilities.MD5(this.inlineResult.content.url));
                sb2.append(".");
                sb2.append(ImageLoader.getHttpUrlExtension(this.inlineResult.content.url, this.documentAttachType != 5 ? "ogg" : "mp3"));
                message.attachPath = new File(directory, sb2.toString()).getAbsolutePath();
            }
            this.currentMessageObject = new MessageObject(this.currentAccount, message, false);
        }
    }

    public void setLink(TLRPC.BotInlineResult contextResult, boolean media, boolean divider, boolean shadow) {
        this.needDivider = divider;
        this.needShadow = shadow;
        this.inlineResult = contextResult;
        this.parentObject = contextResult;
        if (contextResult != null) {
            this.documentAttach = contextResult.document;
            this.photoAttach = this.inlineResult.photo;
        } else {
            this.documentAttach = null;
            this.photoAttach = null;
        }
        this.mediaWebpage = media;
        setAttachType();
        requestLayout();
        updateButtonState(false, false);
    }

    public void setGif(TLRPC.Document document, boolean divider) {
        this.needDivider = divider;
        this.needShadow = false;
        this.inlineResult = null;
        this.parentObject = "gif" + document;
        this.documentAttach = document;
        this.photoAttach = null;
        this.mediaWebpage = true;
        setAttachType();
        requestLayout();
        updateButtonState(false, false);
    }

    public boolean isSticker() {
        return this.documentAttachType == 6;
    }

    public boolean isGif() {
        return this.documentAttachType == 2 && this.canPreviewGif;
    }

    public boolean showingBitmap() {
        return this.linkImageView.getBitmap() != null;
    }

    public TLRPC.Document getDocument() {
        return this.documentAttach;
    }

    public TLRPC.BotInlineResult getBotInlineResult() {
        return this.inlineResult;
    }

    public ImageReceiver getPhotoImage() {
        return this.linkImageView;
    }

    public void setScaled(boolean value) {
        this.scaled = value;
        this.lastUpdateTime = System.currentTimeMillis();
        invalidate();
    }

    public void setCanPreviewGif(boolean value) {
        this.canPreviewGif = value;
    }

    public boolean isCanPreviewGif() {
        return this.canPreviewGif;
    }

    @Override // android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (this.drawLinkImageView) {
            this.linkImageView.onDetachedFromWindow();
        }
        this.radialProgress.onDetachedFromWindow();
        DownloadController.getInstance(this.currentAccount).removeLoadingFileObserver(this);
    }

    @Override // android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.drawLinkImageView && this.linkImageView.onAttachedToWindow()) {
            updateButtonState(false, false);
        }
        this.radialProgress.onAttachedToWindow();
    }

    public MessageObject getMessageObject() {
        return this.currentMessageObject;
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        if (this.mediaWebpage || this.delegate == null || this.inlineResult == null) {
            return super.onTouchEvent(event);
        }
        int x = (int) event.getX();
        int y = (int) event.getY();
        boolean result = false;
        AndroidUtilities.dp(48.0f);
        int i = this.documentAttachType;
        if (i == 3 || i == 5) {
            boolean area = this.letterDrawable.getBounds().contains(x, y);
            if (event.getAction() == 0) {
                if (area) {
                    this.buttonPressed = true;
                    this.radialProgress.setPressed(true, false);
                    invalidate();
                    result = true;
                }
            } else if (this.buttonPressed) {
                if (event.getAction() == 1) {
                    this.buttonPressed = false;
                    playSoundEffect(0);
                    didPressedButton();
                    invalidate();
                } else if (event.getAction() == 3) {
                    this.buttonPressed = false;
                    invalidate();
                } else if (event.getAction() == 2 && !area) {
                    this.buttonPressed = false;
                    invalidate();
                }
                this.radialProgress.setPressed(this.buttonPressed, false);
            }
        } else {
            TLRPC.BotInlineResult botInlineResult = this.inlineResult;
            if (botInlineResult != null && botInlineResult.content != null && !TextUtils.isEmpty(this.inlineResult.content.url)) {
                if (event.getAction() == 0) {
                    if (this.letterDrawable.getBounds().contains(x, y)) {
                        this.buttonPressed = true;
                        result = true;
                    }
                } else if (this.buttonPressed) {
                    if (event.getAction() == 1) {
                        this.buttonPressed = false;
                        playSoundEffect(0);
                        this.delegate.didPressedImage(this);
                    } else if (event.getAction() == 3) {
                        this.buttonPressed = false;
                    } else if (event.getAction() == 2 && !this.letterDrawable.getBounds().contains(x, y)) {
                        this.buttonPressed = false;
                    }
                }
            }
        }
        if (!result) {
            return super.onTouchEvent(event);
        }
        return result;
    }

    private void didPressedButton() {
        int i = this.documentAttachType;
        if (i == 3 || i == 5) {
            int i2 = this.buttonState;
            if (i2 == 0) {
                if (MediaController.getInstance().playMessage(this.currentMessageObject)) {
                    this.buttonState = 1;
                    this.radialProgress.setIcon(getIconForCurrentState(), false, true);
                    invalidate();
                    return;
                }
                return;
            }
            if (i2 == 1) {
                boolean result = MediaController.getInstance().lambda$startAudioAgain$5$MediaController(this.currentMessageObject);
                if (result) {
                    this.buttonState = 0;
                    this.radialProgress.setIcon(getIconForCurrentState(), false, true);
                    invalidate();
                    return;
                }
                return;
            }
            if (i2 == 2) {
                this.radialProgress.setProgress(0.0f, false);
                if (this.documentAttach != null) {
                    FileLoader.getInstance(this.currentAccount).loadFile(this.documentAttach, this.inlineResult, 1, 0);
                } else if (this.inlineResult.content instanceof TLRPC.TL_webDocument) {
                    FileLoader.getInstance(this.currentAccount).loadFile(WebFile.createWithWebDocument(this.inlineResult.content), 1, 1);
                }
                this.buttonState = 4;
                this.radialProgress.setIcon(getIconForCurrentState(), false, true);
                invalidate();
                return;
            }
            if (i2 == 4) {
                if (this.documentAttach != null) {
                    FileLoader.getInstance(this.currentAccount).cancelLoadFile(this.documentAttach);
                } else if (this.inlineResult.content instanceof TLRPC.TL_webDocument) {
                    FileLoader.getInstance(this.currentAccount).cancelLoadFile(WebFile.createWithWebDocument(this.inlineResult.content));
                }
                this.buttonState = 2;
                this.radialProgress.setIcon(getIconForCurrentState(), false, true);
                invalidate();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:88:0x030d  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    protected void onDraw(android.graphics.Canvas r15) {
        /*
            Method dump skipped, instruction units count: 943
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.cells.ContextLinkCell.onDraw(android.graphics.Canvas):void");
    }

    private int getIconForCurrentState() {
        int i = this.documentAttachType;
        if (i == 3 || i == 5) {
            this.radialProgress.setColors(Theme.key_chat_inLoader, Theme.key_chat_inLoaderSelected, Theme.key_chat_inMediaIcon, Theme.key_chat_inMediaIconSelected);
            int i2 = this.buttonState;
            if (i2 == 1) {
                return 1;
            }
            if (i2 == 2) {
                return 2;
            }
            return i2 == 4 ? 3 : 0;
        }
        this.radialProgress.setColors(Theme.key_chat_mediaLoaderPhoto, Theme.key_chat_mediaLoaderPhotoSelected, Theme.key_chat_mediaLoaderPhotoIcon, Theme.key_chat_mediaLoaderPhotoIconSelected);
        return this.buttonState == 1 ? 10 : 4;
    }

    public void updateButtonState(boolean ifSame, boolean animated) {
        boolean isLoading;
        String fileName = null;
        File cacheFile = null;
        int i = this.documentAttachType;
        if (i == 5 || i == 3) {
            TLRPC.Document document = this.documentAttach;
            if (document != null) {
                fileName = FileLoader.getAttachFileName(document);
                cacheFile = FileLoader.getPathToAttach(this.documentAttach);
            } else if (this.inlineResult.content instanceof TLRPC.TL_webDocument) {
                StringBuilder sb = new StringBuilder();
                sb.append(Utilities.MD5(this.inlineResult.content.url));
                sb.append(".");
                sb.append(ImageLoader.getHttpUrlExtension(this.inlineResult.content.url, this.documentAttachType == 5 ? "mp3" : "ogg"));
                fileName = sb.toString();
                cacheFile = new File(FileLoader.getDirectory(4), fileName);
            }
        } else if (this.mediaWebpage) {
            TLRPC.BotInlineResult botInlineResult = this.inlineResult;
            if (botInlineResult != null) {
                if (botInlineResult.document instanceof TLRPC.TL_document) {
                    fileName = FileLoader.getAttachFileName(this.inlineResult.document);
                    cacheFile = FileLoader.getPathToAttach(this.inlineResult.document);
                } else if (this.inlineResult.photo instanceof TLRPC.TL_photo) {
                    TLRPC.PhotoSize closestPhotoSizeWithSize = FileLoader.getClosestPhotoSizeWithSize(this.inlineResult.photo.sizes, AndroidUtilities.getPhotoSize(), true);
                    this.currentPhotoObject = closestPhotoSizeWithSize;
                    fileName = FileLoader.getAttachFileName(closestPhotoSizeWithSize);
                    cacheFile = FileLoader.getPathToAttach(this.currentPhotoObject);
                } else if (this.inlineResult.content instanceof TLRPC.TL_webDocument) {
                    fileName = Utilities.MD5(this.inlineResult.content.url) + "." + ImageLoader.getHttpUrlExtension(this.inlineResult.content.url, "jpg");
                    cacheFile = new File(FileLoader.getDirectory(4), fileName);
                } else if (this.inlineResult.thumb instanceof TLRPC.TL_webDocument) {
                    fileName = Utilities.MD5(this.inlineResult.thumb.url) + "." + ImageLoader.getHttpUrlExtension(this.inlineResult.thumb.url, "jpg");
                    cacheFile = new File(FileLoader.getDirectory(4), fileName);
                }
            } else {
                TLRPC.Document document2 = this.documentAttach;
                if (document2 != null) {
                    fileName = FileLoader.getAttachFileName(document2);
                    cacheFile = FileLoader.getPathToAttach(this.documentAttach);
                }
            }
        }
        if (TextUtils.isEmpty(fileName)) {
            return;
        }
        if (!cacheFile.exists()) {
            DownloadController.getInstance(this.currentAccount).addLoadingFileObserver(fileName, this);
            int i2 = this.documentAttachType;
            if (i2 == 5 || i2 == 3) {
                if (this.documentAttach != null) {
                    isLoading = FileLoader.getInstance(this.currentAccount).isLoadingFile(fileName);
                } else {
                    isLoading = ImageLoader.getInstance().isLoadingHttpFile(fileName);
                }
                if (!isLoading) {
                    this.buttonState = 2;
                    this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated);
                } else {
                    this.buttonState = 4;
                    Float progress = ImageLoader.getInstance().getFileProgress(fileName);
                    if (progress != null) {
                        this.radialProgress.setProgress(progress.floatValue(), animated);
                    } else {
                        this.radialProgress.setProgress(0.0f, animated);
                    }
                    this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated);
                }
            } else {
                this.buttonState = 1;
                Float progress2 = ImageLoader.getInstance().getFileProgress(fileName);
                float setProgress = progress2 != null ? progress2.floatValue() : 0.0f;
                this.radialProgress.setProgress(setProgress, false);
                this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated);
            }
            invalidate();
            return;
        }
        DownloadController.getInstance(this.currentAccount).removeLoadingFileObserver(this);
        int i3 = this.documentAttachType;
        if (i3 == 5 || i3 == 3) {
            boolean playing = MediaController.getInstance().isPlayingMessage(this.currentMessageObject);
            if (!playing || (playing && MediaController.getInstance().isMessagePaused())) {
                this.buttonState = 0;
            } else {
                this.buttonState = 1;
            }
            this.radialProgress.setProgress(1.0f, animated);
        } else {
            this.buttonState = -1;
        }
        this.radialProgress.setIcon(getIconForCurrentState(), ifSame, animated);
        invalidate();
    }

    public void setDelegate(ContextLinkCellDelegate contextLinkCellDelegate) {
        this.delegate = contextLinkCellDelegate;
    }

    public TLRPC.BotInlineResult getResult() {
        return this.inlineResult;
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onFailedDownload(String fileName, boolean canceled) {
        updateButtonState(true, canceled);
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onSuccessDownload(String fileName) {
        this.radialProgress.setProgress(1.0f, true);
        updateButtonState(false, true);
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onProgressDownload(String fileName, float progress) {
        this.radialProgress.setProgress(progress, true);
        int i = this.documentAttachType;
        if (i == 3 || i == 5) {
            if (this.buttonState != 4) {
                updateButtonState(false, true);
            }
        } else if (this.buttonState != 1) {
            updateButtonState(false, true);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public void onProgressUpload(String fileName, float progress, boolean isEncrypted) {
    }

    @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
    public int getObserverTag() {
        return this.TAG;
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        StringBuilder sbuf = new StringBuilder();
        switch (this.documentAttachType) {
            case 1:
                sbuf.append(LocaleController.getString("AttachDocument", R.string.AttachDocument));
                break;
            case 2:
                sbuf.append(LocaleController.getString("AttachGif", R.string.AttachGif));
                break;
            case 3:
                sbuf.append(LocaleController.getString("AttachAudio", R.string.AttachAudio));
                break;
            case 4:
                sbuf.append(LocaleController.getString("AttachVideo", R.string.AttachVideo));
                break;
            case 5:
                sbuf.append(LocaleController.getString("AttachMusic", R.string.AttachMusic));
                if (this.descriptionLayout != null && this.titleLayout != null) {
                    sbuf.append(", ");
                    sbuf.append(LocaleController.formatString("AccDescrMusicInfo", R.string.AccDescrMusicInfo, this.descriptionLayout.getText(), this.titleLayout.getText()));
                }
                break;
            case 6:
                sbuf.append(LocaleController.getString("AttachSticker", R.string.AttachSticker));
                break;
            case 7:
                sbuf.append(LocaleController.getString("AttachPhoto", R.string.AttachPhoto));
                break;
            case 8:
                sbuf.append(LocaleController.getString("AttachLocation", R.string.AttachLocation));
                break;
            default:
                StaticLayout staticLayout = this.titleLayout;
                if (staticLayout != null && !TextUtils.isEmpty(staticLayout.getText())) {
                    sbuf.append(this.titleLayout.getText());
                }
                StaticLayout staticLayout2 = this.descriptionLayout;
                if (staticLayout2 != null && !TextUtils.isEmpty(staticLayout2.getText())) {
                    if (sbuf.length() > 0) {
                        sbuf.append(", ");
                    }
                    sbuf.append(this.descriptionLayout.getText());
                }
                break;
        }
        info.setText(sbuf);
    }
}
