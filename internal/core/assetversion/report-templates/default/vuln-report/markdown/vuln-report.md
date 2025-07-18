\tableofcontents

\newpage

# KPI Overview

\begin{tikzpicture}

% First row: Critical & High
\node[rounded corners=25pt, fill=red!80, minimum width=7.5cm, minimum height=3cm, align=center] at (0,0) {\textbf{\Huge 2}\\[3pt]\textbf{\large Critical Vulnerabilities}};
\node[rounded corners=25pt, fill=orange!90!yellow!70, minimum width=7.5cm, minimum height=3cm, align=center] at (8.5,0) {\textbf{\Huge 4}\\[3pt]\textbf{\large High Vulnerabilities}};

% Second row: Medium & Low
\node[rounded corners=25pt, fill=yellow!80!brown!60, minimum width=7.5cm, minimum height=3cm, align=center] at (0,-4) {\textbf{\Huge 8}\\[3pt]\textbf{\large Medium Vulnerabilities}};
\node[rounded corners=25pt, fill=green!70!black, minimum width=7.5cm, minimum height=3cm, align=center] at (8.5,-4) {\textbf{\Huge 20}\\[3pt]\textbf{\large Low Vulnerabilities}};

\end{tikzpicture}

\begin{tikzpicture}
    \begin{axis}
        \addplot[color=red]{exp(x)};
    \end{axis}
\end{tikzpicture}

[This is a Link](https://google.de)

\newpage

# Vulnerabilities

Summary: A total of X critical security vulnerabilities were identified.
These are listed and described according to their risk score. If available, a suggested solution is
provided.
The critical vulnerabilities were closed with an average processing time of X.

\newpage

# Critical Risk Vulnerabilities {.unnumbered}

## Vuln 1 {.unnumbered}

This is a Markdown Table:

| Month    | Savings |
| -------- | ------- |
| January  | $250    |
| February | $80     |
| March    | $420    |


This is a LaTeX Table:

\begin{center}
\begin{tabular}{ c c c }
 cell1 & cell2 & cell3 \\ 
 cell4 & cell5 & cell6 \\  
 cell7 & cell8 & cell9    
\end{tabular}
\end{center}

\newpage

## Vuln 2 {.unnumbered}

Status: Criticial

Description: Command Injection..

Identifier: CVE-2025-XYZ

Recommended Action: There's nothing you can do

\newpage

# High Risk Vulnerabilities {.unnumbered}

## Vuln 1 {.unnumbered}

This is the first page

\newpage

## Vuln 2 {.unnumbered}

This is the second page??

\newpage

# Medium Risk Vulnerabilities {.unnumbered}

## Vuln 1  {.unnumbered}

This is the first page

\newpage

## Vuln 2  {.unnumbered}

This is the second page??

\newpage

# Low Risk Vulnerabilities {.unnumbered}

## Vuln 1 {.unnumbered}

This is the first page

\newpage

## Vuln 2 {.unnumbered}

This is the second page??