package androidx.constraintlayout.solver;

import java.util.ArrayList;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class Metrics {
    public long additionalMeasures;
    public long barrierConnectionResolved;
    public long bfs;
    public long centerConnectionResolved;
    public long chainConnectionResolved;
    public long constraints;
    public long determineGroups;
    public long errors;
    public long extravariables;
    public long fullySolved;
    public long graphOptimizer;
    public long graphSolved;
    public long grouping;
    public long infeasibleDetermineGroups;
    public long iterations;
    public long lastTableSize;
    public long layouts;
    public long linearSolved;
    public long matchConnectionResolved;
    public long maxRows;
    public long maxTableSize;
    public long maxVariables;
    public long measuredMatchWidgets;
    public long measuredWidgets;
    public long measures;
    public long measuresLayoutDuration;
    public long measuresWidgetsDuration;
    public long measuresWrap;
    public long measuresWrapInfeasible;
    public long minimize;
    public long minimizeGoal;
    public long nonresolvedWidgets;
    public long oldresolvedWidgets;
    public long optimize;
    public long pivots;
    public ArrayList<String> problematicLayouts = new ArrayList<>();
    public long resolutions;
    public long resolvedWidgets;
    public long simpleconstraints;
    public long slackvariables;
    public long tableSizeIncrease;
    public long variables;
    public long widgets;

    public void reset() {
        this.measures = 0L;
        this.widgets = 0L;
        this.additionalMeasures = 0L;
        this.resolutions = 0L;
        this.tableSizeIncrease = 0L;
        this.maxTableSize = 0L;
        this.lastTableSize = 0L;
        this.maxVariables = 0L;
        this.maxRows = 0L;
        this.minimize = 0L;
        this.minimizeGoal = 0L;
        this.constraints = 0L;
        this.simpleconstraints = 0L;
        this.optimize = 0L;
        this.iterations = 0L;
        this.pivots = 0L;
        this.bfs = 0L;
        this.variables = 0L;
        this.errors = 0L;
        this.slackvariables = 0L;
        this.extravariables = 0L;
        this.fullySolved = 0L;
        this.graphOptimizer = 0L;
        this.graphSolved = 0L;
        this.resolvedWidgets = 0L;
        this.oldresolvedWidgets = 0L;
        this.nonresolvedWidgets = 0L;
        this.centerConnectionResolved = 0L;
        this.matchConnectionResolved = 0L;
        this.chainConnectionResolved = 0L;
        this.barrierConnectionResolved = 0L;
        this.problematicLayouts.clear();
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("\n*** Metrics ***\nmeasures: ");
        m586H.append(this.measures);
        m586H.append("\nmeasuresWrap: ");
        m586H.append(this.measuresWrap);
        m586H.append("\nmeasuresWrapInfeasible: ");
        m586H.append(this.measuresWrapInfeasible);
        m586H.append("\ndetermineGroups: ");
        m586H.append(this.determineGroups);
        m586H.append("\ninfeasibleDetermineGroups: ");
        m586H.append(this.infeasibleDetermineGroups);
        m586H.append("\ngraphOptimizer: ");
        m586H.append(this.graphOptimizer);
        m586H.append("\nwidgets: ");
        m586H.append(this.widgets);
        m586H.append("\ngraphSolved: ");
        m586H.append(this.graphSolved);
        m586H.append("\nlinearSolved: ");
        m586H.append(this.linearSolved);
        m586H.append("\n");
        return m586H.toString();
    }
}
