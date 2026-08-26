"use client";

import React, { Component, ErrorInfo, ReactNode } from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";

interface ErrorBoundaryProps {
  children: ReactNode;
  /** Label shown in the error fallback (e.g. the module name). */
  moduleName?: string;
  /** Called when the user clicks "Retry" - typically re-mounts the component. */
  onRetry?: () => void;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

/**
 * Catches render-time exceptions in any child component tree and displays
 * a recovery panel instead of crashing the entire app to a white screen.
 * Each module in AppShell is wrapped in its own ErrorBoundary so a failure
 * in one module doesn't take down the sidebar, header, or other modules.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error(
      `[Clarity365 ErrorBoundary] ${this.props.moduleName || "Component"} crashed:`,
      error,
      errorInfo.componentStack
    );
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
    this.props.onRetry?.();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full min-h-[300px] p-8 text-center">
          <div className="w-12 h-12 rounded-full bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 flex items-center justify-center mb-4">
            <AlertTriangle size={22} className="text-red-500 dark:text-red-400" />
          </div>
          <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100 mb-1">
            {this.props.moduleName || "Module"} encountered an error
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mb-4">
            {this.state.error?.message || "An unexpected rendering error occurred. This module crashed but the rest of Clarity365 is still running."}
          </p>
          <button
            onClick={this.handleRetry}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-slate-900 dark:bg-slate-700 hover:bg-slate-800 dark:hover:bg-slate-600 rounded-sm transition-colors"
          >
            <RotateCcw size={12} />
            <span>Retry</span>
          </button>
          {this.state.error && (
            <details className="mt-4 text-left w-full max-w-lg">
              <summary className="text-[11px] text-slate-400 dark:text-slate-500 cursor-pointer hover:text-slate-600 dark:hover:text-slate-300">
                Technical details
              </summary>
              <pre className="mt-2 p-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-sm text-[10px] text-slate-600 dark:text-slate-300 font-mono overflow-x-auto whitespace-pre-wrap">
                {this.state.error.stack || this.state.error.message}
              </pre>
            </details>
          )}
        </div>
      );
    }

    return this.props.children;
  }
}
