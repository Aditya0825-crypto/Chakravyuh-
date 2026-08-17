import { useRef } from "react";
import { stages } from "../data/stages";
import { Eyebrow } from "./Atoms";
import ConduitLine from "./ConduitLine";
import PipelineStage from "./PipelineStage";
import BugFindingDiagram from "./BugFindingDiagram";
import EvidenceCard from "./EvidenceCard";
import PatchEngineViz from "./PatchEngineViz";
import HumanGatePanel from "./HumanGatePanel";

export default function PipelineSection() {
  const containerRef = useRef(null);

  return (
    <section id="pipeline" className="relative px-6 md:px-10 py-24 md:py-32">
      <div className="mx-auto max-w-[1000px]">
        <Eyebrow accent="signal">The Architecture</Eyebrow>
        <h2 className="mt-5 font-display text-3xl md:text-5xl font-medium tracking-tight text-ink-1 max-w-2xl">
          Six stages. One reasoning pipeline. Nothing ships without proof.
        </h2>
        <p className="mt-4 text-ink-2 text-lg max-w-2xl">
          Every candidate bug travels the same path — found, proven, matched against precedent,
          fixed by competing agents, and gated by a human. No shortcuts.
        </p>
      </div>

      <div ref={containerRef} className="relative mt-16 max-w-[1000px] mx-auto">
        <ConduitLine containerRef={containerRef} />

        <PipelineStage stage={stages[0]} />

        <PipelineStage stage={stages[1]}>
          <BugFindingDiagram />
        </PipelineStage>

        <PipelineStage stage={stages[2]} />

        <PipelineStage stage={stages[3]}>
          <EvidenceCard />
        </PipelineStage>

        <PipelineStage stage={stages[4]}>
          <PatchEngineViz />
        </PipelineStage>

        <PipelineStage stage={stages[5]}>
          <HumanGatePanel />
        </PipelineStage>
      </div>
    </section>
  );
}
