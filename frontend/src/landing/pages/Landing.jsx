import BackgroundField from "../components/BackgroundField";
import Navbar from "../components/Navbar";
import Hero from "../components/Hero";
import ProblemSection from "../components/ProblemSection";
import PipelineSection from "../components/PipelineSection";
import JudgeCriteriaGrid from "../components/JudgeCriteriaGrid";
import DifferentiatorGrid from "../components/DifferentiatorGrid";
import TechStackPanel from "../components/TechStackPanel";
import DemoTerminal from "../components/DemoTerminal";
import ClosingPositioning from "../components/ClosingPositioning";
import Footer from "../components/Footer";

export default function Landing() {
  return (
    <div className="relative min-h-screen">
      <BackgroundField />
      <div className="grain-overlay" />
      <div className="scanlines" />
      <Navbar />
      <main>
        <Hero />
        <ProblemSection />
        <PipelineSection />
        <JudgeCriteriaGrid />
        <DifferentiatorGrid />
        <TechStackPanel />
        <DemoTerminal />
        <ClosingPositioning />
      </main>
      <Footer />
    </div>
  );
}
