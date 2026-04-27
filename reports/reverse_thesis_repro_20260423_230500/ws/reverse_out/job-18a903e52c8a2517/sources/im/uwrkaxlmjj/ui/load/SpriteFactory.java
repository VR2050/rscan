package im.uwrkaxlmjj.ui.load;

import im.uwrkaxlmjj.ui.load.sprite.Sprite;
import im.uwrkaxlmjj.ui.load.style.ChasingDots;
import im.uwrkaxlmjj.ui.load.style.Circle;
import im.uwrkaxlmjj.ui.load.style.CubeGrid;
import im.uwrkaxlmjj.ui.load.style.DoubleBounce;
import im.uwrkaxlmjj.ui.load.style.FadingCircle;
import im.uwrkaxlmjj.ui.load.style.FoldingCube;
import im.uwrkaxlmjj.ui.load.style.MultiplePulse;
import im.uwrkaxlmjj.ui.load.style.MultiplePulseRing;
import im.uwrkaxlmjj.ui.load.style.Pulse;
import im.uwrkaxlmjj.ui.load.style.PulseRing;
import im.uwrkaxlmjj.ui.load.style.RotatingCircle;
import im.uwrkaxlmjj.ui.load.style.RotatingPlane;
import im.uwrkaxlmjj.ui.load.style.ThreeBounce;
import im.uwrkaxlmjj.ui.load.style.WanderingCubes;
import im.uwrkaxlmjj.ui.load.style.Wave;

/* JADX INFO: loaded from: classes5.dex */
public class SpriteFactory {

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.load.SpriteFactory$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$im$uwrkaxlmjj$ui$load$Style;

        static {
            int[] iArr = new int[Style.values().length];
            $SwitchMap$im$uwrkaxlmjj$ui$load$Style = iArr;
            try {
                iArr[Style.ROTATING_PLANE.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.DOUBLE_BOUNCE.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.WAVE.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.WANDERING_CUBES.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.PULSE.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.CHASING_DOTS.ordinal()] = 6;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.THREE_BOUNCE.ordinal()] = 7;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.CIRCLE.ordinal()] = 8;
            } catch (NoSuchFieldError e8) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.CUBE_GRID.ordinal()] = 9;
            } catch (NoSuchFieldError e9) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.FADING_CIRCLE.ordinal()] = 10;
            } catch (NoSuchFieldError e10) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.FOLDING_CUBE.ordinal()] = 11;
            } catch (NoSuchFieldError e11) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.ROTATING_CIRCLE.ordinal()] = 12;
            } catch (NoSuchFieldError e12) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.MULTIPLE_PULSE.ordinal()] = 13;
            } catch (NoSuchFieldError e13) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.PULSE_RING.ordinal()] = 14;
            } catch (NoSuchFieldError e14) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$load$Style[Style.MULTIPLE_PULSE_RING.ordinal()] = 15;
            } catch (NoSuchFieldError e15) {
            }
        }
    }

    public static Sprite create(Style style) {
        switch (AnonymousClass1.$SwitchMap$im$uwrkaxlmjj$ui$load$Style[style.ordinal()]) {
            case 1:
                Sprite sprite = new RotatingPlane();
                return sprite;
            case 2:
                Sprite sprite2 = new DoubleBounce();
                return sprite2;
            case 3:
                Sprite sprite3 = new Wave();
                return sprite3;
            case 4:
                Sprite sprite4 = new WanderingCubes();
                return sprite4;
            case 5:
                Sprite sprite5 = new Pulse();
                return sprite5;
            case 6:
                Sprite sprite6 = new ChasingDots();
                return sprite6;
            case 7:
                Sprite sprite7 = new ThreeBounce();
                return sprite7;
            case 8:
                Sprite sprite8 = new Circle();
                return sprite8;
            case 9:
                Sprite sprite9 = new CubeGrid();
                return sprite9;
            case 10:
                Sprite sprite10 = new FadingCircle();
                return sprite10;
            case 11:
                Sprite sprite11 = new FoldingCube();
                return sprite11;
            case 12:
                Sprite sprite12 = new RotatingCircle();
                return sprite12;
            case 13:
                Sprite sprite13 = new MultiplePulse();
                return sprite13;
            case 14:
                Sprite sprite14 = new PulseRing();
                return sprite14;
            case 15:
                Sprite sprite15 = new MultiplePulseRing();
                return sprite15;
            default:
                return null;
        }
    }
}
