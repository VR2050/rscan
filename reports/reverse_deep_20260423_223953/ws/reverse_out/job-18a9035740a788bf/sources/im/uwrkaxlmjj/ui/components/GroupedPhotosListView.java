package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.View;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes5.dex */
public class GroupedPhotosListView extends View implements GestureDetector.OnGestureListener {
    private boolean animateAllLine;
    private int animateToDX;
    private int animateToDXStart;
    private int animateToItem;
    private Paint backgroundPaint;
    private long currentGroupId;
    private int currentImage;
    private float currentItemProgress;
    private ArrayList<Object> currentObjects;
    public ArrayList<ImageLocation> currentPhotos;
    private GroupedPhotosListViewDelegate delegate;
    private int drawDx;
    private GestureDetector gestureDetector;
    private boolean ignoreChanges;
    private ArrayList<ImageReceiver> imagesToDraw;
    private int itemHeight;
    private int itemSpacing;
    private int itemWidth;
    private int itemY;
    private long lastUpdateTime;
    private float moveLineProgress;
    private boolean moving;
    private int nextImage;
    private float nextItemProgress;
    private int nextPhotoScrolling;
    private android.widget.Scroller scroll;
    private boolean scrolling;
    private boolean stopedScrolling;
    private ArrayList<ImageReceiver> unusedReceivers;

    public interface GroupedPhotosListViewDelegate {
        int getAvatarsDialogId();

        int getCurrentAccount();

        int getCurrentIndex();

        ArrayList<MessageObject> getImagesArr();

        ArrayList<ImageLocation> getImagesArrLocations();

        ArrayList<TLRPC.PageBlock> getPageBlockArr();

        Object getParentObject();

        int getSlideshowMessageId();

        void setCurrentIndex(int i);
    }

    public GroupedPhotosListView(Context context) {
        super(context);
        this.backgroundPaint = new Paint();
        this.unusedReceivers = new ArrayList<>();
        this.imagesToDraw = new ArrayList<>();
        this.currentPhotos = new ArrayList<>();
        this.currentObjects = new ArrayList<>();
        this.currentItemProgress = 1.0f;
        this.nextItemProgress = 0.0f;
        this.animateToItem = -1;
        this.nextPhotoScrolling = -1;
        this.gestureDetector = new GestureDetector(context, this);
        this.scroll = new android.widget.Scroller(context);
        this.itemWidth = AndroidUtilities.dp(42.0f);
        this.itemHeight = AndroidUtilities.dp(56.0f);
        this.itemSpacing = AndroidUtilities.dp(1.0f);
        this.itemY = AndroidUtilities.dp(3.0f);
        this.backgroundPaint.setColor(Theme.ACTION_BAR_PHOTO_VIEWER_COLOR);
    }

    public void clear() {
        this.currentPhotos.clear();
        this.currentObjects.clear();
        this.imagesToDraw.clear();
    }

    public void fillList() {
        ArrayList<ImageLocation> imagesArrLocations;
        boolean changed;
        int currentAccount;
        int i;
        int min;
        ArrayList<MessageObject> imagesArr;
        int i2;
        if (this.ignoreChanges) {
            this.ignoreChanges = false;
            return;
        }
        int currentIndex = this.delegate.getCurrentIndex();
        ArrayList<ImageLocation> imagesArrLocations2 = this.delegate.getImagesArrLocations();
        ArrayList<MessageObject> imagesArr2 = this.delegate.getImagesArr();
        ArrayList<TLRPC.PageBlock> pageBlockArr = this.delegate.getPageBlockArr();
        int slideshowMessageId = this.delegate.getSlideshowMessageId();
        int currentAccount2 = this.delegate.getCurrentAccount();
        boolean changed2 = false;
        int newCount = 0;
        Object currentObject = null;
        if (imagesArrLocations2 != null && !imagesArrLocations2.isEmpty()) {
            ImageLocation location = imagesArrLocations2.get(currentIndex);
            newCount = imagesArrLocations2.size();
            currentObject = location;
            imagesArrLocations = imagesArrLocations2;
        } else if (imagesArr2 == null || imagesArr2.isEmpty()) {
            imagesArrLocations = imagesArrLocations2;
            if (pageBlockArr != null && !pageBlockArr.isEmpty()) {
                TLRPC.PageBlock pageBlock = pageBlockArr.get(currentIndex);
                currentObject = pageBlock;
                if (pageBlock.groupId != this.currentGroupId) {
                    changed2 = true;
                    this.currentGroupId = pageBlock.groupId;
                } else {
                    int size = pageBlockArr.size();
                    for (int a = currentIndex; a < size; a++) {
                        TLRPC.PageBlock object = pageBlockArr.get(a);
                        if (object.groupId != this.currentGroupId) {
                            break;
                        }
                        newCount++;
                    }
                    for (int a2 = currentIndex - 1; a2 >= 0; a2--) {
                        TLRPC.PageBlock object2 = pageBlockArr.get(a2);
                        if (object2.groupId != this.currentGroupId) {
                            break;
                        }
                        newCount++;
                    }
                    changed2 = false;
                }
            } else {
                changed2 = false;
            }
        } else {
            MessageObject messageObject = imagesArr2.get(currentIndex);
            currentObject = messageObject;
            if (messageObject.getGroupIdForUse() != this.currentGroupId) {
                changed2 = true;
                this.currentGroupId = messageObject.getGroupIdForUse();
                imagesArrLocations = imagesArrLocations2;
            } else {
                int max = Math.min(currentIndex + 10, imagesArr2.size());
                int a3 = currentIndex;
                while (true) {
                    if (a3 >= max) {
                        imagesArrLocations = imagesArrLocations2;
                        break;
                    }
                    MessageObject object3 = imagesArr2.get(a3);
                    if (slideshowMessageId == 0) {
                        imagesArrLocations = imagesArrLocations2;
                        if (object3.getGroupIdForUse() != this.currentGroupId) {
                            break;
                        }
                    } else {
                        imagesArrLocations = imagesArrLocations2;
                    }
                    newCount++;
                    a3++;
                    imagesArrLocations2 = imagesArrLocations;
                }
                int min2 = Math.max(currentIndex - 10, 0);
                int a4 = currentIndex - 1;
                while (true) {
                    if (a4 < min2) {
                        changed = changed2;
                        break;
                    }
                    MessageObject object4 = imagesArr2.get(a4);
                    if (slideshowMessageId == 0) {
                        currentAccount = currentAccount2;
                        changed = changed2;
                        if (object4.getGroupIdForUse() != this.currentGroupId) {
                            break;
                        }
                    } else {
                        currentAccount = currentAccount2;
                        changed = changed2;
                    }
                    newCount++;
                    a4--;
                    currentAccount2 = currentAccount;
                    changed2 = changed;
                }
                changed2 = changed;
            }
        }
        if (currentObject == null) {
            return;
        }
        if (!changed2) {
            if (newCount != this.currentPhotos.size() || this.currentObjects.indexOf(currentObject) == -1) {
                changed2 = true;
            } else {
                int newImageIndex = this.currentObjects.indexOf(currentObject);
                int i3 = this.currentImage;
                if (i3 != newImageIndex && newImageIndex != -1) {
                    if (!this.animateAllLine) {
                        fillImages(true, (i3 - newImageIndex) * (this.itemWidth + this.itemSpacing));
                        this.currentImage = newImageIndex;
                        i2 = 0;
                        this.moving = false;
                    } else {
                        this.animateToItem = newImageIndex;
                        this.nextImage = newImageIndex;
                        this.animateToDX = (i3 - newImageIndex) * (this.itemWidth + this.itemSpacing);
                        this.moving = true;
                        this.animateAllLine = false;
                        this.lastUpdateTime = System.currentTimeMillis();
                        invalidate();
                        i2 = 0;
                    }
                    this.drawDx = i2;
                }
            }
        }
        if (changed2) {
            this.animateAllLine = false;
            this.currentPhotos.clear();
            this.currentObjects.clear();
            if (imagesArrLocations != null && !imagesArrLocations.isEmpty()) {
                ArrayList<ImageLocation> imagesArrLocations3 = imagesArrLocations;
                this.currentObjects.addAll(imagesArrLocations3);
                this.currentPhotos.addAll(imagesArrLocations3);
                this.currentImage = currentIndex;
                this.animateToItem = -1;
            } else if (imagesArr2 == null || imagesArr2.isEmpty()) {
                if (pageBlockArr != null && !pageBlockArr.isEmpty() && this.currentGroupId != 0) {
                    int a5 = currentIndex;
                    int size2 = pageBlockArr.size();
                    while (a5 < size2) {
                        TLRPC.PageBlock object5 = pageBlockArr.get(a5);
                        int slideshowMessageId2 = slideshowMessageId;
                        if (object5.groupId != this.currentGroupId) {
                            break;
                        }
                        this.currentObjects.add(object5);
                        this.currentPhotos.add(ImageLocation.getForObject(object5.thumb, object5.thumbObject));
                        a5++;
                        slideshowMessageId = slideshowMessageId2;
                    }
                    this.currentImage = 0;
                    this.animateToItem = -1;
                    for (int a6 = currentIndex - 1; a6 >= 0; a6--) {
                        TLRPC.PageBlock object6 = pageBlockArr.get(a6);
                        if (object6.groupId != this.currentGroupId) {
                            break;
                        }
                        this.currentObjects.add(0, object6);
                        this.currentPhotos.add(0, ImageLocation.getForObject(object6.thumb, object6.thumbObject));
                        this.currentImage++;
                    }
                }
            } else if (this.currentGroupId != 0 || slideshowMessageId != 0) {
                int max2 = Math.min(currentIndex + 10, imagesArr2.size());
                int a7 = currentIndex;
                while (true) {
                    i = 56;
                    if (a7 >= max2) {
                        break;
                    }
                    MessageObject object7 = imagesArr2.get(a7);
                    if (slideshowMessageId == 0 && object7.getGroupIdForUse() != this.currentGroupId) {
                        break;
                    }
                    this.currentObjects.add(object7);
                    this.currentPhotos.add(ImageLocation.getForObject(FileLoader.getClosestPhotoSizeWithSize(object7.photoThumbs, 56, true), object7.photoThumbsObject));
                    a7++;
                }
                this.currentImage = 0;
                this.animateToItem = -1;
                int min3 = Math.max(currentIndex - 10, 0);
                int a8 = currentIndex - 1;
                while (a8 >= min3) {
                    MessageObject object8 = imagesArr2.get(a8);
                    if (slideshowMessageId == 0) {
                        min = min3;
                        imagesArr = imagesArr2;
                        if (object8.getGroupIdForUse() != this.currentGroupId) {
                            break;
                        }
                    } else {
                        min = min3;
                        imagesArr = imagesArr2;
                    }
                    this.currentObjects.add(0, object8);
                    this.currentPhotos.add(0, ImageLocation.getForObject(FileLoader.getClosestPhotoSizeWithSize(object8.photoThumbs, i, true), object8.photoThumbsObject));
                    this.currentImage++;
                    a8--;
                    imagesArr2 = imagesArr;
                    min3 = min;
                    i = 56;
                }
            }
            if (this.currentPhotos.size() == 1) {
                this.currentPhotos.clear();
                this.currentObjects.clear();
            }
            fillImages(false, 0);
        }
    }

    public void setMoveProgress(float progress) {
        if (this.scrolling || this.animateToItem >= 0) {
            return;
        }
        if (progress > 0.0f) {
            this.nextImage = this.currentImage - 1;
        } else {
            this.nextImage = this.currentImage + 1;
        }
        int i = this.nextImage;
        if (i >= 0 && i < this.currentPhotos.size()) {
            this.currentItemProgress = 1.0f - Math.abs(progress);
        } else {
            this.currentItemProgress = 1.0f;
        }
        this.nextItemProgress = 1.0f - this.currentItemProgress;
        this.moving = progress != 0.0f;
        invalidate();
        if (this.currentPhotos.isEmpty()) {
            return;
        }
        if (progress >= 0.0f || this.currentImage != this.currentPhotos.size() - 1) {
            if (progress > 0.0f && this.currentImage == 0) {
                return;
            }
            int i2 = (int) ((this.itemWidth + this.itemSpacing) * progress);
            this.drawDx = i2;
            fillImages(true, i2);
        }
    }

    private ImageReceiver getFreeReceiver() {
        ImageReceiver receiver;
        if (this.unusedReceivers.isEmpty()) {
            receiver = new ImageReceiver(this);
        } else {
            receiver = this.unusedReceivers.get(0);
            this.unusedReceivers.remove(0);
        }
        this.imagesToDraw.add(receiver);
        receiver.setCurrentAccount(this.delegate.getCurrentAccount());
        return receiver;
    }

    private void fillImages(boolean move, int dx) {
        int addRightIndex;
        int addLeftIndex;
        Object parentObject;
        Object parentObject2;
        int i = 0;
        if (!move && !this.imagesToDraw.isEmpty()) {
            this.unusedReceivers.addAll(this.imagesToDraw);
            this.imagesToDraw.clear();
            this.moving = false;
            this.moveLineProgress = 1.0f;
            this.currentItemProgress = 1.0f;
            this.nextItemProgress = 0.0f;
        }
        invalidate();
        if (getMeasuredWidth() == 0 || this.currentPhotos.isEmpty()) {
            return;
        }
        int width = getMeasuredWidth();
        int startX = (getMeasuredWidth() / 2) - (this.itemWidth / 2);
        if (move) {
            addRightIndex = Integer.MIN_VALUE;
            addLeftIndex = Integer.MAX_VALUE;
            int count = this.imagesToDraw.size();
            int a = 0;
            while (a < count) {
                ImageReceiver receiver = this.imagesToDraw.get(a);
                int num = receiver.getParam();
                int i2 = num - this.currentImage;
                int i3 = this.itemWidth;
                int x = (i2 * (this.itemSpacing + i3)) + startX + dx;
                if (x > width || i3 + x < 0) {
                    this.unusedReceivers.add(receiver);
                    this.imagesToDraw.remove(a);
                    count--;
                    a--;
                }
                addLeftIndex = Math.min(addLeftIndex, num - 1);
                addRightIndex = Math.max(addRightIndex, num + 1);
                a++;
            }
        } else {
            addRightIndex = this.currentImage;
            addLeftIndex = this.currentImage - 1;
        }
        if (addRightIndex != Integer.MIN_VALUE) {
            int count2 = this.currentPhotos.size();
            int a2 = addRightIndex;
            while (a2 < count2) {
                int x2 = ((a2 - this.currentImage) * (this.itemWidth + this.itemSpacing)) + startX + dx;
                if (x2 >= width) {
                    break;
                }
                ImageLocation location = this.currentPhotos.get(a2);
                ImageReceiver receiver2 = getFreeReceiver();
                receiver2.setImageCoords(x2, this.itemY, this.itemWidth, this.itemHeight);
                if (this.currentObjects.get(i) instanceof MessageObject) {
                    parentObject2 = this.currentObjects.get(a2);
                } else if (this.currentObjects.get(i) instanceof TLRPC.PageBlock) {
                    parentObject2 = this.delegate.getParentObject();
                } else {
                    parentObject2 = "avatar_" + this.delegate.getAvatarsDialogId();
                }
                Object parent = parentObject2;
                receiver2.setImage(null, null, location, "80_80", 0, null, parent, 1);
                receiver2.setParam(a2);
                a2++;
                i = 0;
            }
        }
        if (addLeftIndex != Integer.MAX_VALUE) {
            for (int a3 = addLeftIndex; a3 >= 0; a3--) {
                int i4 = a3 - this.currentImage;
                int i5 = this.itemWidth;
                int x3 = (i4 * (this.itemSpacing + i5)) + startX + dx + i5;
                if (x3 > 0) {
                    ImageLocation location2 = this.currentPhotos.get(a3);
                    ImageReceiver receiver3 = getFreeReceiver();
                    receiver3.setImageCoords(x3, this.itemY, this.itemWidth, this.itemHeight);
                    if (this.currentObjects.get(0) instanceof MessageObject) {
                        parentObject = this.currentObjects.get(a3);
                    } else if (this.currentObjects.get(0) instanceof TLRPC.PageBlock) {
                        parentObject = this.delegate.getParentObject();
                    } else {
                        parentObject = "avatar_" + this.delegate.getAvatarsDialogId();
                    }
                    Object parent2 = parentObject;
                    receiver3.setImage(null, null, location2, "80_80", 0, null, parent2, 1);
                    receiver3.setParam(a3);
                } else {
                    return;
                }
            }
        }
    }

    @Override // android.view.GestureDetector.OnGestureListener
    public boolean onDown(MotionEvent e) {
        if (!this.scroll.isFinished()) {
            this.scroll.abortAnimation();
        }
        this.animateToItem = -1;
        return true;
    }

    @Override // android.view.GestureDetector.OnGestureListener
    public void onShowPress(MotionEvent e) {
    }

    @Override // android.view.GestureDetector.OnGestureListener
    public boolean onSingleTapUp(MotionEvent e) {
        int currentIndex = this.delegate.getCurrentIndex();
        ArrayList<ImageLocation> imagesArrLocations = this.delegate.getImagesArrLocations();
        ArrayList<MessageObject> imagesArr = this.delegate.getImagesArr();
        ArrayList<TLRPC.PageBlock> pageBlockArr = this.delegate.getPageBlockArr();
        stopScrolling();
        int count = this.imagesToDraw.size();
        for (int a = 0; a < count; a++) {
            ImageReceiver receiver = this.imagesToDraw.get(a);
            if (receiver.isInsideImage(e.getX(), e.getY())) {
                int num = receiver.getParam();
                if (num < 0 || num >= this.currentObjects.size()) {
                    return true;
                }
                if (imagesArr != null && !imagesArr.isEmpty()) {
                    MessageObject messageObject = (MessageObject) this.currentObjects.get(num);
                    int idx = imagesArr.indexOf(messageObject);
                    if (currentIndex == idx) {
                        return true;
                    }
                    this.moveLineProgress = 1.0f;
                    this.animateAllLine = true;
                    this.delegate.setCurrentIndex(idx);
                    return false;
                }
                if (pageBlockArr != null && !pageBlockArr.isEmpty()) {
                    TLRPC.PageBlock pageBlock = (TLRPC.PageBlock) this.currentObjects.get(num);
                    int idx2 = pageBlockArr.indexOf(pageBlock);
                    if (currentIndex == idx2) {
                        return true;
                    }
                    this.moveLineProgress = 1.0f;
                    this.animateAllLine = true;
                    this.delegate.setCurrentIndex(idx2);
                    return false;
                }
                if (imagesArrLocations != null && !imagesArrLocations.isEmpty()) {
                    ImageLocation location = (ImageLocation) this.currentObjects.get(num);
                    int idx3 = imagesArrLocations.indexOf(location);
                    if (currentIndex == idx3) {
                        return true;
                    }
                    this.moveLineProgress = 1.0f;
                    this.animateAllLine = true;
                    this.delegate.setCurrentIndex(idx3);
                    return false;
                }
                return false;
            }
        }
        return false;
    }

    private void updateAfterScroll() {
        int dx;
        int indexChange;
        int indexChange2 = 0;
        int dx2 = this.drawDx;
        int iAbs = Math.abs(dx2);
        int i = this.itemWidth;
        int i2 = this.itemSpacing;
        if (iAbs > (i / 2) + i2) {
            if (dx2 > 0) {
                dx = dx2 - ((i / 2) + i2);
                indexChange = 0 + 1;
            } else {
                dx = dx2 + (i / 2) + i2;
                indexChange = 0 - 1;
            }
            indexChange2 = indexChange + (dx / (this.itemWidth + (this.itemSpacing * 2)));
        }
        this.nextPhotoScrolling = this.currentImage - indexChange2;
        int currentIndex = this.delegate.getCurrentIndex();
        ArrayList<ImageLocation> imagesArrLocations = this.delegate.getImagesArrLocations();
        ArrayList<MessageObject> imagesArr = this.delegate.getImagesArr();
        ArrayList<TLRPC.PageBlock> pageBlockArr = this.delegate.getPageBlockArr();
        int i3 = this.nextPhotoScrolling;
        if (currentIndex != i3 && i3 >= 0 && i3 < this.currentPhotos.size()) {
            Object photo = this.currentObjects.get(this.nextPhotoScrolling);
            int nextPhoto = -1;
            if (imagesArr != null && !imagesArr.isEmpty()) {
                MessageObject messageObject = (MessageObject) photo;
                nextPhoto = imagesArr.indexOf(messageObject);
            } else if (pageBlockArr != null && !pageBlockArr.isEmpty()) {
                TLRPC.PageBlock pageBlock = (TLRPC.PageBlock) photo;
                nextPhoto = pageBlockArr.indexOf(pageBlock);
            } else if (imagesArrLocations != null && !imagesArrLocations.isEmpty()) {
                ImageLocation location = (ImageLocation) photo;
                nextPhoto = imagesArrLocations.indexOf(location);
            }
            if (nextPhoto >= 0) {
                this.ignoreChanges = true;
                this.delegate.setCurrentIndex(nextPhoto);
            }
        }
        if (!this.scrolling) {
            this.scrolling = true;
            this.stopedScrolling = false;
        }
        fillImages(true, this.drawDx);
    }

    @Override // android.view.GestureDetector.OnGestureListener
    public boolean onScroll(MotionEvent e1, MotionEvent e2, float distanceX, float distanceY) {
        this.drawDx = (int) (this.drawDx - distanceX);
        int min = getMinScrollX();
        int max = getMaxScrollX();
        int i = this.drawDx;
        if (i < min) {
            this.drawDx = min;
        } else if (i > max) {
            this.drawDx = max;
        }
        updateAfterScroll();
        return false;
    }

    @Override // android.view.GestureDetector.OnGestureListener
    public void onLongPress(MotionEvent e) {
    }

    @Override // android.view.GestureDetector.OnGestureListener
    public boolean onFling(MotionEvent e1, MotionEvent e2, float velocityX, float velocityY) {
        this.scroll.abortAnimation();
        if (this.currentPhotos.size() >= 10) {
            this.scroll.fling(this.drawDx, 0, Math.round(velocityX), 0, getMinScrollX(), getMaxScrollX(), 0, 0);
            return false;
        }
        return false;
    }

    private void stopScrolling() {
        this.scrolling = false;
        if (!this.scroll.isFinished()) {
            this.scroll.abortAnimation();
        }
        int i = this.nextPhotoScrolling;
        if (i >= 0 && i < this.currentObjects.size()) {
            this.stopedScrolling = true;
            int i2 = this.nextPhotoScrolling;
            this.animateToItem = i2;
            this.nextImage = i2;
            this.animateToDX = (this.currentImage - i2) * (this.itemWidth + this.itemSpacing);
            this.animateToDXStart = this.drawDx;
            this.moveLineProgress = 1.0f;
            this.nextPhotoScrolling = -1;
        }
        invalidate();
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent event) {
        if (this.currentPhotos.isEmpty() || getAlpha() != 1.0f) {
            return false;
        }
        boolean result = this.gestureDetector.onTouchEvent(event) || super.onTouchEvent(event);
        if (this.scrolling && event.getAction() == 1 && this.scroll.isFinished()) {
            stopScrolling();
        }
        return result;
    }

    private int getMinScrollX() {
        return (-((this.currentPhotos.size() - this.currentImage) - 1)) * (this.itemWidth + (this.itemSpacing * 2));
    }

    private int getMaxScrollX() {
        return this.currentImage * (this.itemWidth + (this.itemSpacing * 2));
    }

    @Override // android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        super.onLayout(changed, left, top, right, bottom);
        fillImages(false, 0);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        int trueWidth;
        int nextTrueWidth;
        int count;
        int maxItemWidth;
        if (this.imagesToDraw.isEmpty()) {
            return;
        }
        canvas.drawRect(0.0f, 0.0f, getMeasuredWidth(), getMeasuredHeight(), this.backgroundPaint);
        int count2 = this.imagesToDraw.size();
        int moveX = this.drawDx;
        int maxItemWidth2 = (int) (this.itemWidth * 2.0f);
        int padding = AndroidUtilities.dp(8.0f);
        ImageLocation object = this.currentPhotos.get(this.currentImage);
        if (object != null && object.photoSize != null) {
            trueWidth = Math.max(this.itemWidth, (int) (object.photoSize.w * (this.itemHeight / object.photoSize.h)));
        } else {
            trueWidth = this.itemHeight;
        }
        int trueWidth2 = Math.min(maxItemWidth2, trueWidth);
        float f = this.currentItemProgress;
        int currentPaddings = (int) (padding * 2 * f);
        int trueWidth3 = this.itemWidth + ((int) ((trueWidth2 - r9) * f)) + currentPaddings;
        int trueWidth4 = this.nextImage;
        if (trueWidth4 >= 0 && trueWidth4 < this.currentPhotos.size()) {
            ImageLocation object2 = this.currentPhotos.get(this.nextImage);
            if (object2 != null && object2.photoSize != null) {
                nextTrueWidth = Math.max(this.itemWidth, (int) (object2.photoSize.w * (this.itemHeight / object2.photoSize.h)));
            } else {
                nextTrueWidth = this.itemHeight;
            }
        } else {
            nextTrueWidth = this.itemWidth;
        }
        int nextTrueWidth2 = Math.min(maxItemWidth2, nextTrueWidth);
        float f2 = this.nextItemProgress;
        int nextPaddings = (int) (padding * 2 * f2);
        int moveX2 = (int) (moveX + ((((nextTrueWidth2 + nextPaddings) - this.itemWidth) / 2) * f2 * (this.nextImage > this.currentImage ? -1 : 1)));
        int nextTrueWidth3 = this.itemWidth + ((int) ((nextTrueWidth2 - r10) * this.nextItemProgress)) + nextPaddings;
        int nextTrueWidth4 = getMeasuredWidth();
        int startX = (nextTrueWidth4 - trueWidth3) / 2;
        int a = 0;
        while (a < count2) {
            ImageReceiver receiver = this.imagesToDraw.get(a);
            int num = receiver.getParam();
            int i = this.currentImage;
            if (num == i) {
                receiver.setImageX(startX + moveX2 + (currentPaddings / 2));
                receiver.setImageWidth(trueWidth3 - currentPaddings);
                count = count2;
                maxItemWidth = maxItemWidth2;
            } else {
                int i2 = this.nextImage;
                if (i2 < i) {
                    if (num < i) {
                        if (num <= i2) {
                            int param = (receiver.getParam() - this.currentImage) + 1;
                            int i3 = this.itemWidth;
                            count = count2;
                            int count3 = this.itemSpacing;
                            receiver.setImageX((((param * (i3 + count3)) + startX) - (count3 + nextTrueWidth3)) + moveX2);
                            maxItemWidth = maxItemWidth2;
                        } else {
                            count = count2;
                            int count4 = receiver.getParam();
                            receiver.setImageX(((count4 - this.currentImage) * (this.itemWidth + this.itemSpacing)) + startX + moveX2);
                            maxItemWidth = maxItemWidth2;
                        }
                    } else {
                        count = count2;
                        int count5 = startX + trueWidth3;
                        maxItemWidth = maxItemWidth2;
                        receiver.setImageX(count5 + this.itemSpacing + (((receiver.getParam() - this.currentImage) - 1) * (this.itemWidth + this.itemSpacing)) + moveX2);
                    }
                } else {
                    count = count2;
                    maxItemWidth = maxItemWidth2;
                    if (num < i) {
                        receiver.setImageX(((receiver.getParam() - this.currentImage) * (this.itemWidth + this.itemSpacing)) + startX + moveX2);
                    } else if (num <= i2) {
                        receiver.setImageX(startX + trueWidth3 + this.itemSpacing + (((receiver.getParam() - this.currentImage) - 1) * (this.itemWidth + this.itemSpacing)) + moveX2);
                    } else {
                        int i4 = startX + trueWidth3 + this.itemSpacing;
                        int param2 = (receiver.getParam() - this.currentImage) - 2;
                        int i5 = this.itemWidth;
                        int i6 = this.itemSpacing;
                        receiver.setImageX(i4 + (param2 * (i5 + i6)) + i6 + nextTrueWidth3 + moveX2);
                    }
                }
                if (num == this.nextImage) {
                    receiver.setImageWidth(nextTrueWidth3 - nextPaddings);
                    receiver.setImageX(receiver.getImageX() + (nextPaddings / 2));
                } else {
                    receiver.setImageWidth(this.itemWidth);
                }
            }
            receiver.draw(canvas);
            a++;
            count2 = count;
            maxItemWidth2 = maxItemWidth;
        }
        long newTime = System.currentTimeMillis();
        long dt = newTime - this.lastUpdateTime;
        if (dt > 17) {
            dt = 17;
        }
        this.lastUpdateTime = newTime;
        int i7 = this.animateToItem;
        if (i7 >= 0) {
            float f3 = this.moveLineProgress;
            if (f3 > 0.0f) {
                this.moveLineProgress = f3 - (dt / 200.0f);
                if (i7 != this.currentImage) {
                    this.nextItemProgress = CubicBezierInterpolator.EASE_OUT.getInterpolation(1.0f - this.moveLineProgress);
                    if (!this.stopedScrolling) {
                        this.currentItemProgress = CubicBezierInterpolator.EASE_OUT.getInterpolation(this.moveLineProgress);
                        this.drawDx = (int) Math.ceil(this.nextItemProgress * this.animateToDX);
                    } else {
                        float f4 = this.currentItemProgress;
                        if (f4 > 0.0f) {
                            float f5 = f4 - (dt / 200.0f);
                            this.currentItemProgress = f5;
                            if (f5 < 0.0f) {
                                this.currentItemProgress = 0.0f;
                            }
                        }
                        this.drawDx = this.animateToDXStart + ((int) Math.ceil(this.nextItemProgress * (this.animateToDX - r1)));
                    }
                } else {
                    float f6 = this.currentItemProgress;
                    if (f6 < 1.0f) {
                        float f7 = f6 + (dt / 200.0f);
                        this.currentItemProgress = f7;
                        if (f7 > 1.0f) {
                            this.currentItemProgress = 1.0f;
                        }
                    }
                    this.drawDx = this.animateToDXStart + ((int) Math.ceil(this.currentItemProgress * (this.animateToDX - r1)));
                }
                if (this.moveLineProgress <= 0.0f) {
                    this.currentImage = this.animateToItem;
                    this.moveLineProgress = 1.0f;
                    this.currentItemProgress = 1.0f;
                    this.nextItemProgress = 0.0f;
                    this.moving = false;
                    this.stopedScrolling = false;
                    this.drawDx = 0;
                    this.animateToItem = -1;
                }
            }
            fillImages(true, this.drawDx);
            invalidate();
        }
        if (this.scrolling) {
            float f8 = this.currentItemProgress;
            if (f8 > 0.0f) {
                float f9 = f8 - (dt / 200.0f);
                this.currentItemProgress = f9;
                if (f9 < 0.0f) {
                    this.currentItemProgress = 0.0f;
                }
                invalidate();
            }
        }
        if (!this.scroll.isFinished()) {
            if (this.scroll.computeScrollOffset()) {
                this.drawDx = this.scroll.getCurrX();
                updateAfterScroll();
                invalidate();
            }
            if (this.scroll.isFinished()) {
                stopScrolling();
            }
        }
    }

    public void setDelegate(GroupedPhotosListViewDelegate groupedPhotosListViewDelegate) {
        this.delegate = groupedPhotosListViewDelegate;
    }
}
