package im.uwrkaxlmjj.ui.load.style;

import android.animation.ValueAnimator;
import android.graphics.Rect;
import androidx.recyclerview.widget.ItemTouchHelper;
import im.uwrkaxlmjj.ui.load.animation.SpriteAnimatorBuilder;
import im.uwrkaxlmjj.ui.load.sprite.RectSprite;
import im.uwrkaxlmjj.ui.load.sprite.Sprite;
import im.uwrkaxlmjj.ui.load.sprite.SpriteContainer;

/* JADX INFO: loaded from: classes5.dex */
public class CubeGrid extends SpriteContainer {
    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer
    public Sprite[] onCreateChild() {
        int[] delays = {ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, 300, 400, 100, ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, 300, 0, 100, ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION};
        GridItem[] gridItems = new GridItem[9];
        for (int i = 0; i < gridItems.length; i++) {
            gridItems[i] = new GridItem();
            gridItems[i].setAnimationDelay(delays[i]);
        }
        return gridItems;
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer, im.uwrkaxlmjj.ui.load.sprite.Sprite, android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect bounds) {
        super.onBoundsChange(bounds);
        Rect bounds2 = clipSquare(bounds);
        int width = (int) (bounds2.width() * 0.33f);
        int height = (int) (bounds2.height() * 0.33f);
        for (int i = 0; i < getChildCount(); i++) {
            int x = i % 3;
            int y = i / 3;
            int l = bounds2.left + (x * width);
            int t = bounds2.top + (y * height);
            Sprite sprite = getChildAt(i);
            sprite.setDrawBounds(l, t, l + width, t + height);
        }
    }

    private class GridItem extends RectSprite {
        private GridItem() {
        }

        @Override // im.uwrkaxlmjj.ui.load.sprite.RectSprite, im.uwrkaxlmjj.ui.load.sprite.Sprite
        public ValueAnimator onCreateAnimation() {
            float[] fractions = {0.0f, 0.35f, 0.7f, 1.0f};
            SpriteAnimatorBuilder spriteAnimatorBuilder = new SpriteAnimatorBuilder(this);
            Float fValueOf = Float.valueOf(1.0f);
            return spriteAnimatorBuilder.scale(fractions, fValueOf, Float.valueOf(0.0f), fValueOf, fValueOf).duration(1300L).easeInOut(fractions).build();
        }
    }
}
