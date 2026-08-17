import { Check, Loader2 } from "lucide-react";
import { stageOrder, stageLabels } from "../../data/scans";

export default function StageStepper({ currentStage, isRunning }) {
  const currentIndex = stageOrder.indexOf(currentStage);

  return (
    <div className="flex items-center overflow-x-auto pb-1">
      {stageOrder.map((stage, i) => {
        const isDone = i < currentIndex || (i === currentIndex && !isRunning);
        const isActive = i === currentIndex && isRunning;
        const isPending = i > currentIndex;

        return (
          <div key={stage} className="flex items-center shrink-0">
            <div className="flex flex-col items-center gap-2 min-w-[92px]">
              <div
                className={`w-8 h-8 rounded-full border-2 flex items-center justify-center ${
                  isDone
                    ? "border-signal bg-signal/15 text-signal"
                    : isActive
                    ? "border-amber bg-amber/15 text-amber"
                    : "border-line text-ink-3"
                }`}
              >
                {isDone ? (
                  <Check size={14} />
                ) : isActive ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <span className="font-mono text-[10px]">{i + 1}</span>
                )}
              </div>
              <span
                className={`font-mono text-[10px] uppercase tracking-widest text-center ${
                  isDone ? "text-ink-1" : isActive ? "text-amber" : "text-ink-3"
                }`}
              >
                {stageLabels[stage]}
              </span>
            </div>
            {i < stageOrder.length - 1 && (
              <div className={`w-8 md:w-12 h-px mb-5 ${isDone ? "bg-signal/50" : "bg-line"}`} />
            )}
          </div>
        );
      })}
    </div>
  );
}
