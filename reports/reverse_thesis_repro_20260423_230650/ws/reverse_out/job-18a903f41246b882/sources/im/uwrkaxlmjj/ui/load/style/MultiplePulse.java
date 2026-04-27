package im.uwrkaxlmjj.ui.load.style;

import androidx.recyclerview.widget.ItemTouchHelper;
import im.uwrkaxlmjj.ui.load.sprite.Sprite;
import im.uwrkaxlmjj.ui.load.sprite.SpriteContainer;

/* JADX INFO: loaded from: classes5.dex */
public class MultiplePulse extends SpriteContainer {
    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer
    public Sprite[] onCreateChild() {
        return new Sprite[]{new Pulse(), new Pulse(), new Pulse()};
    }

    @Override // im.uwrkaxlmjj.ui.load.sprite.SpriteContainer
    public void onChildCreated(Sprite... sprites) {
        for (int i = 0; i < sprites.length; i++) {
            sprites[i].setAnimationDelay((i + 1) * ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION);
        }
    }
}
